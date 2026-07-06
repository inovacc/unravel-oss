"""A simulated Django-style application with ORM, signals, middleware, and class-based views.

Demonstrates: Django ORM patterns, signals, middleware, class-based views,
              Meta classes, model managers, querysets, decorators.
Difficulty: Very Hard (~450 LOC)

NOTE: This is a standalone simulation of Django patterns, not actual Django code.
It demonstrates the patterns that togo would need to convert.
"""

from __future__ import annotations

import datetime
import hashlib
import json
import re
import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, ClassVar


# --- Signals ---

class Signal:
    """Django-style signal dispatcher."""

    def __init__(self, name: str) -> None:
        self.name = name
        self._receivers: list[Callable[..., None]] = []

    def connect(self, receiver: Callable[..., None]) -> None:
        if receiver not in self._receivers:
            self._receivers.append(receiver)

    def disconnect(self, receiver: Callable[..., None]) -> None:
        self._receivers = [r for r in self._receivers if r != receiver]

    def send(self, sender: type, **kwargs: Any) -> list[tuple[Callable, Any]]:
        results: list[tuple[Callable, Any]] = []
        for receiver in self._receivers:
            try:
                result = receiver(sender=sender, **kwargs)
                results.append((receiver, result))
            except Exception as e:
                results.append((receiver, e))
        return results


# Pre-defined signals
pre_save = Signal("pre_save")
post_save = Signal("post_save")
pre_delete = Signal("pre_delete")
post_delete = Signal("post_delete")


def receiver(signal: Signal, sender: type | None = None) -> Callable:
    """Decorator to register a signal receiver."""
    def decorator(func: Callable) -> Callable:
        if sender is not None:
            original_func = func
            def filtered_receiver(*, sender: type, **kwargs: Any) -> Any:
                return original_func(sender=sender, **kwargs)
            signal.connect(filtered_receiver)
        else:
            signal.connect(func)
        return func
    return decorator


# --- QuerySet ---

class QuerySet:
    """Django-style QuerySet for filtering and querying model instances."""

    def __init__(self, model_class: type, data: list[dict[str, Any]] | None = None) -> None:
        self._model_class = model_class
        self._data: list[dict[str, Any]] = data if data is not None else []
        self._filters: list[Callable[[dict[str, Any]], bool]] = []
        self._order_by: list[str] = []
        self._limit: int | None = None
        self._offset: int = 0

    def filter(self, **kwargs: Any) -> QuerySet:
        """Filter records matching all given field=value conditions."""
        new_qs = QuerySet(self._model_class, list(self._data))
        new_qs._filters = list(self._filters)
        new_qs._order_by = list(self._order_by)

        for field_name, value in kwargs.items():
            lookup = "exact"
            parts = field_name.split("__")
            if len(parts) == 2:
                field_name, lookup = parts[0], parts[1]

            if lookup == "exact":
                new_qs._filters.append(lambda r, f=field_name, v=value: r.get(f) == v)
            elif lookup == "contains":
                new_qs._filters.append(lambda r, f=field_name, v=value: v in str(r.get(f, "")))
            elif lookup == "gt":
                new_qs._filters.append(lambda r, f=field_name, v=value: r.get(f, 0) > v)
            elif lookup == "lt":
                new_qs._filters.append(lambda r, f=field_name, v=value: r.get(f, 0) < v)
            elif lookup == "gte":
                new_qs._filters.append(lambda r, f=field_name, v=value: r.get(f, 0) >= v)
            elif lookup == "lte":
                new_qs._filters.append(lambda r, f=field_name, v=value: r.get(f, 0) <= v)
            elif lookup == "in":
                new_qs._filters.append(lambda r, f=field_name, v=value: r.get(f) in v)
            elif lookup == "isnull":
                new_qs._filters.append(lambda r, f=field_name, v=value: (r.get(f) is None) == v)

        return new_qs

    def exclude(self, **kwargs: Any) -> QuerySet:
        """Exclude records matching given conditions."""
        included = self.filter(**kwargs)._evaluate()
        excluded_ids = {r.get("id") for r in included}
        remaining = [r for r in self._evaluate_base() if r.get("id") not in excluded_ids]
        return QuerySet(self._model_class, remaining)

    def order_by(self, *fields: str) -> QuerySet:
        """Order results by given fields (prefix with - for descending)."""
        new_qs = QuerySet(self._model_class, list(self._data))
        new_qs._filters = list(self._filters)
        new_qs._order_by = list(fields)
        return new_qs

    def first(self) -> dict[str, Any] | None:
        """Return first matching record."""
        results = self._evaluate()
        return results[0] if results else None

    def last(self) -> dict[str, Any] | None:
        """Return last matching record."""
        results = self._evaluate()
        return results[-1] if results else None

    def count(self) -> int:
        """Return number of matching records."""
        return len(self._evaluate())

    def exists(self) -> bool:
        """Return True if any records match."""
        return self.count() > 0

    def values(self, *fields: str) -> list[dict[str, Any]]:
        """Return list of dicts with only specified fields."""
        results = self._evaluate()
        if not fields:
            return results
        return [{f: r.get(f) for f in fields} for r in results]

    def all(self) -> list[dict[str, Any]]:
        """Return all matching records."""
        return self._evaluate()

    def _evaluate_base(self) -> list[dict[str, Any]]:
        return list(self._data)

    def _evaluate(self) -> list[dict[str, Any]]:
        results = list(self._data)

        for f in self._filters:
            results = [r for r in results if f(r)]

        for order_field in reversed(self._order_by):
            reverse = order_field.startswith("-")
            field_name = order_field.lstrip("-")
            results.sort(key=lambda r: r.get(field_name, ""), reverse=reverse)

        if self._offset:
            results = results[self._offset:]
        if self._limit is not None:
            results = results[:self._limit]

        return results


# --- Model Meta & Manager ---

class ModelMeta(type):
    """Metaclass for Django-style models that processes Meta inner class."""

    def __new__(mcs, name: str, bases: tuple[type, ...], namespace: dict[str, Any]) -> type:
        cls = super().__new__(mcs, name, bases, namespace)

        if name == "Model":
            return cls

        # Process Meta inner class
        meta = namespace.get("Meta")
        if meta:
            cls._db_table = getattr(meta, "db_table", name.lower())
            cls._ordering = getattr(meta, "ordering", [])
            cls._verbose_name = getattr(meta, "verbose_name", name)
            cls._unique_together = getattr(meta, "unique_together", [])
        else:
            cls._db_table = name.lower()
            cls._ordering = []
            cls._verbose_name = name
            cls._unique_together = []

        # Initialize storage
        cls._storage: list[dict[str, Any]] = []
        cls.objects = Manager(cls)

        return cls


class Manager:
    """Django-style model manager."""

    def __init__(self, model_class: type) -> None:
        self._model_class = model_class

    def all(self) -> QuerySet:
        return QuerySet(self._model_class, list(self._model_class._storage))

    def filter(self, **kwargs: Any) -> QuerySet:
        return self.all().filter(**kwargs)

    def get(self, **kwargs: Any) -> dict[str, Any]:
        qs = self.filter(**kwargs)
        results = qs.all()
        if len(results) == 0:
            raise ValueError(f"{self._model_class.__name__} matching query does not exist")
        if len(results) > 1:
            raise ValueError(f"Multiple {self._model_class.__name__} returned")
        return results[0]

    def create(self, **kwargs: Any) -> dict[str, Any]:
        if "id" not in kwargs:
            kwargs["id"] = str(uuid.uuid4())
        if "created_at" not in kwargs:
            kwargs["created_at"] = datetime.datetime.now(datetime.timezone.utc).isoformat()

        pre_save.send(sender=self._model_class, instance=kwargs, created=True)
        self._model_class._storage.append(kwargs)
        post_save.send(sender=self._model_class, instance=kwargs, created=True)

        return kwargs

    def count(self) -> int:
        return len(self._model_class._storage)


# --- Models ---

class Model(metaclass=ModelMeta):
    """Base model class."""
    pass


class User(Model):
    class Meta:
        db_table = "auth_user"
        ordering = ["-created_at"]
        verbose_name = "User"

    @staticmethod
    def hash_password(password: str) -> str:
        return hashlib.sha256(password.encode()).hexdigest()


class Article(Model):
    class Meta:
        db_table = "blog_article"
        ordering = ["-created_at"]
        verbose_name = "Article"
        unique_together = [("slug",)]


class Comment(Model):
    class Meta:
        db_table = "blog_comment"
        ordering = ["created_at"]
        verbose_name = "Comment"


# --- Middleware ---

@dataclass
class Request:
    method: str
    path: str
    headers: dict[str, str] = field(default_factory=dict)
    body: str = ""
    user: dict[str, Any] | None = None
    META: dict[str, Any] = field(default_factory=dict)


@dataclass
class Response:
    status_code: int = 200
    content: str = ""
    headers: dict[str, str] = field(default_factory=lambda: {"Content-Type": "application/json"})

    @staticmethod
    def json(data: Any, status: int = 200) -> Response:
        return Response(status_code=status, content=json.dumps(data, indent=2))


class MiddlewareBase(ABC):
    """Django-style middleware base."""

    def __init__(self, get_response: Callable[[Request], Response]) -> None:
        self._get_response = get_response

    @abstractmethod
    def __call__(self, request: Request) -> Response:
        ...

    def process_request(self, request: Request) -> Response | None:
        return None

    def process_response(self, request: Request, response: Response) -> Response:
        return response


class AuthMiddleware(MiddlewareBase):
    """Simulated authentication middleware."""

    PUBLIC_PATHS: ClassVar[set[str]] = {"/", "/login", "/register", "/health"}

    def __call__(self, request: Request) -> Response:
        if request.path not in self.PUBLIC_PATHS:
            auth_header = request.headers.get("Authorization", "")
            if not auth_header.startswith("Bearer "):
                return Response.json({"error": "Authentication required"}, status=401)
            request.user = {"id": "user-1", "username": "testuser"}

        return self._get_response(request)


class LoggingMiddleware(MiddlewareBase):
    """Request/response logging middleware."""

    def __call__(self, request: Request) -> Response:
        response = self._get_response(request)
        return response


class CORSMiddleware(MiddlewareBase):
    """CORS headers middleware."""

    ALLOWED_ORIGINS: ClassVar[list[str]] = ["http://localhost:3000", "https://example.com"]

    def __call__(self, request: Request) -> Response:
        response = self._get_response(request)
        origin = request.headers.get("Origin", "")
        if origin in self.ALLOWED_ORIGINS:
            response.headers["Access-Control-Allow-Origin"] = origin
            response.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE"
            response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
        return response


# --- Class-Based Views ---

class View(ABC):
    """Base class-based view."""

    http_method_names: ClassVar[list[str]] = ["get", "post", "put", "patch", "delete"]

    def dispatch(self, request: Request) -> Response:
        method = request.method.lower()
        if method not in self.http_method_names:
            return Response.json({"error": "Method not allowed"}, status=405)

        handler = getattr(self, method, None)
        if handler is None:
            return Response.json({"error": "Method not allowed"}, status=405)

        return handler(request)


class ListView(View):
    """View for listing model instances."""
    model: ClassVar[type]
    paginate_by: ClassVar[int] = 20

    def get(self, request: Request) -> Response:
        qs = self.model.objects.all()
        items = qs.all()
        return Response.json({
            "count": len(items),
            "results": items[:self.paginate_by],
        })


class DetailView(View):
    """View for single model instance."""
    model: ClassVar[type]

    def get_object_id(self, request: Request) -> str:
        parts = request.path.strip("/").split("/")
        return parts[-1] if parts else ""

    def get(self, request: Request) -> Response:
        obj_id = self.get_object_id(request)
        try:
            obj = self.model.objects.get(id=obj_id)
            return Response.json(obj)
        except ValueError:
            return Response.json({"error": "Not found"}, status=404)


class CreateView(View):
    """View for creating model instances."""
    model: ClassVar[type]
    required_fields: ClassVar[list[str]] = []

    def post(self, request: Request) -> Response:
        try:
            data = json.loads(request.body)
        except json.JSONDecodeError:
            return Response.json({"error": "Invalid JSON"}, status=400)

        missing = [f for f in self.required_fields if f not in data]
        if missing:
            return Response.json({"error": f"Missing fields: {missing}"}, status=400)

        obj = self.model.objects.create(**data)
        return Response.json(obj, status=201)


# --- Concrete Views ---

class ArticleListView(ListView):
    model = Article
    paginate_by = 10


class ArticleDetailView(DetailView):
    model = Article


class ArticleCreateView(CreateView):
    model = Article
    required_fields = ["title", "content", "author_id"]


# --- URL Router ---

@dataclass
class URLPattern:
    pattern: str
    view: View
    name: str = ""

    def match(self, path: str) -> bool:
        regex = re.sub(r"<(\w+)>", r"([^/]+)", self.pattern)
        return bool(re.fullmatch(regex, path))


class URLRouter:
    """Simple URL router mapping paths to views."""

    def __init__(self) -> None:
        self._patterns: list[URLPattern] = []

    def add(self, pattern: str, view: View, name: str = "") -> None:
        self._patterns.append(URLPattern(pattern=pattern, view=view, name=name))

    def resolve(self, path: str) -> View | None:
        for url_pattern in self._patterns:
            if url_pattern.match(path):
                return url_pattern.view
        return None


# --- Application ---

class DjangoApp:
    """Simulated Django application."""

    def __init__(self, name: str) -> None:
        self.name = name
        self._router = URLRouter()
        self._middleware_classes: list[type] = []

    def add_middleware(self, middleware_class: type) -> None:
        self._middleware_classes.append(middleware_class)

    def add_url(self, pattern: str, view: View, name: str = "") -> None:
        self._router.add(pattern, view, name)

    def handle_request(self, request: Request) -> Response:
        """Process a request through middleware and routing."""

        def get_response(req: Request) -> Response:
            view = self._router.resolve(req.path)
            if view is None:
                return Response.json({"error": "Not found"}, status=404)
            return view.dispatch(req)

        # Build middleware chain (innermost first)
        handler = get_response
        for middleware_class in reversed(self._middleware_classes):
            handler = middleware_class(handler)

        return handler(request)


# --- Signal handlers ---

@receiver(post_save)
def on_model_save(*, sender: type, instance: dict[str, Any], created: bool = False, **kwargs: Any) -> None:
    action = "created" if created else "updated"
    _ = f"Signal: {sender.__name__} {action}: {instance.get('id', 'unknown')}"


def main() -> None:
    # Build application
    app = DjangoApp("blog")

    # Add middleware
    app.add_middleware(CORSMiddleware)
    app.add_middleware(LoggingMiddleware)
    app.add_middleware(AuthMiddleware)

    # Add routes
    app.add_url("/articles", ArticleListView(), name="article-list")
    app.add_url("/articles/create", ArticleCreateView(), name="article-create")
    app.add_url("/articles/<id>", ArticleDetailView(), name="article-detail")

    # Create some users
    User.objects.create(
        username="alice",
        email="alice@example.com",
        password=User.hash_password("secret123"),
    )
    User.objects.create(
        username="bob",
        email="bob@example.com",
        password=User.hash_password("password456"),
    )

    # Create articles (via API)
    articles_data = [
        {"title": "First Post", "content": "Hello world!", "slug": "first-post", "author_id": "user-1"},
        {"title": "Python Tips", "content": "Use type hints.", "slug": "python-tips", "author_id": "user-1"},
        {"title": "Go Patterns", "content": "Embrace interfaces.", "slug": "go-patterns", "author_id": "user-2"},
    ]

    print("=== Creating Articles ===")
    for data in articles_data:
        req = Request(
            method="POST",
            path="/articles/create",
            headers={"Authorization": "Bearer test-token", "Content-Type": "application/json"},
            body=json.dumps(data),
        )
        resp = app.handle_request(req)
        article = json.loads(resp.content)
        print(f"  Created: {article.get('title')} (status: {resp.status_code})")

    # List articles
    print("\n=== Listing Articles ===")
    req = Request(
        method="GET",
        path="/articles",
        headers={"Authorization": "Bearer test-token"},
    )
    resp = app.handle_request(req)
    data = json.loads(resp.content)
    print(f"  Total: {data['count']}")
    for article in data["results"]:
        print(f"  - {article['title']} (by {article.get('author_id', 'unknown')})")

    # Test auth required
    print("\n=== Auth Test ===")
    req = Request(method="GET", path="/articles")
    resp = app.handle_request(req)
    print(f"  No auth: status={resp.status_code}")

    req = Request(method="GET", path="/articles", headers={"Authorization": "Bearer valid"})
    resp = app.handle_request(req)
    print(f"  With auth: status={resp.status_code}")

    # QuerySet operations
    print("\n=== QuerySet Operations ===")
    all_articles = Article.objects.all().all()
    print(f"  All articles: {len(all_articles)}")

    filtered = Article.objects.filter(author_id="user-1").all()
    print(f"  By author user-1: {len(filtered)}")

    first = Article.objects.all().first()
    print(f"  First article: {first.get('title') if first else 'None'}")

    count = Article.objects.count()
    print(f"  Total count: {count}")

    # Model metadata
    print("\n=== Model Metadata ===")
    print(f"  Article table: {Article._db_table}")
    print(f"  Article verbose: {Article._verbose_name}")
    print(f"  User table: {User._db_table}")
    print(f"  User count: {User.objects.count()}")


if __name__ == "__main__":
    main()
