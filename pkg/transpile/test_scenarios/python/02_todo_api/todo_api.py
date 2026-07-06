"""A TODO API with in-memory storage, JSON serialization, and HTTP handler patterns.

Demonstrates: dataclasses, JSON, HTTP handler patterns, type annotations, enums, UUID.
Difficulty: Medium (~250 LOC)
"""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from http import HTTPStatus
from typing import Any


class Priority(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class TaskStatus(Enum):
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    CANCELLED = "cancelled"


@dataclass
class Tag:
    name: str
    color: str = "#808080"


@dataclass
class Task:
    title: str
    description: str = ""
    priority: Priority = Priority.MEDIUM
    status: TaskStatus = TaskStatus.PENDING
    tags: list[Tag] = field(default_factory=list)
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    updated_at: str = ""
    due_date: str | None = None
    assignee: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to a JSON-serializable dict."""
        d = asdict(self)
        d["priority"] = self.priority.value
        d["status"] = self.status.value
        return d

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Task:
        """Create a Task from a dict (e.g., from JSON)."""
        tags = [Tag(**t) if isinstance(t, dict) else t for t in data.get("tags", [])]
        return cls(
            title=data["title"],
            description=data.get("description", ""),
            priority=Priority(data.get("priority", "medium")),
            status=TaskStatus(data.get("status", "pending")),
            tags=tags,
            id=data.get("id", str(uuid.uuid4())),
            created_at=data.get("created_at", datetime.now(timezone.utc).isoformat()),
            updated_at=data.get("updated_at", ""),
            due_date=data.get("due_date"),
            assignee=data.get("assignee"),
        )


class TaskNotFoundError(Exception):
    def __init__(self, task_id: str) -> None:
        super().__init__(f"Task not found: {task_id}")
        self.task_id = task_id


class ValidationError(Exception):
    def __init__(self, field: str, message: str) -> None:
        super().__init__(f"Validation error on '{field}': {message}")
        self.field = field


@dataclass
class TaskFilter:
    status: TaskStatus | None = None
    priority: Priority | None = None
    assignee: str | None = None
    tag: str | None = None


class TaskStore:
    """In-memory task store with CRUD operations."""

    def __init__(self) -> None:
        self._tasks: dict[str, Task] = {}

    def create(self, task: Task) -> Task:
        """Add a new task to the store."""
        self._validate_task(task)
        self._tasks[task.id] = task
        return task

    def get(self, task_id: str) -> Task:
        """Retrieve a task by ID."""
        task = self._tasks.get(task_id)
        if task is None:
            raise TaskNotFoundError(task_id)
        return task

    def update(self, task_id: str, updates: dict[str, Any]) -> Task:
        """Update specific fields of a task."""
        task = self.get(task_id)

        if "title" in updates:
            task.title = updates["title"]
        if "description" in updates:
            task.description = updates["description"]
        if "priority" in updates:
            task.priority = Priority(updates["priority"])
        if "status" in updates:
            task.status = TaskStatus(updates["status"])
        if "assignee" in updates:
            task.assignee = updates["assignee"]
        if "due_date" in updates:
            task.due_date = updates["due_date"]

        task.updated_at = datetime.now(timezone.utc).isoformat()
        self._validate_task(task)
        return task

    def delete(self, task_id: str) -> None:
        """Remove a task from the store."""
        if task_id not in self._tasks:
            raise TaskNotFoundError(task_id)
        del self._tasks[task_id]

    def list_tasks(self, filter_by: TaskFilter | None = None) -> list[Task]:
        """Return all tasks, optionally filtered."""
        tasks = list(self._tasks.values())

        if filter_by is not None:
            if filter_by.status is not None:
                tasks = [t for t in tasks if t.status == filter_by.status]
            if filter_by.priority is not None:
                tasks = [t for t in tasks if t.priority == filter_by.priority]
            if filter_by.assignee is not None:
                tasks = [t for t in tasks if t.assignee == filter_by.assignee]
            if filter_by.tag is not None:
                tasks = [t for t in tasks if any(tag.name == filter_by.tag for tag in t.tags)]

        return sorted(tasks, key=lambda t: t.created_at)

    def count(self) -> int:
        """Return total number of tasks."""
        return len(self._tasks)

    def stats(self) -> dict[str, int]:
        """Return task counts grouped by status."""
        result: dict[str, int] = {}
        for status in TaskStatus:
            count = sum(1 for t in self._tasks.values() if t.status == status)
            result[status.value] = count
        return result

    @staticmethod
    def _validate_task(task: Task) -> None:
        if not task.title.strip():
            raise ValidationError("title", "Title cannot be empty")
        if len(task.title) > 200:
            raise ValidationError("title", "Title exceeds maximum length of 200")


@dataclass
class Response:
    """Simulated HTTP response."""
    status: int
    body: str
    headers: dict[str, str] = field(default_factory=lambda: {"Content-Type": "application/json"})


class TodoHandler:
    """HTTP-like request handler for the TODO API."""

    def __init__(self) -> None:
        self._store = TaskStore()

    def handle_create(self, body: str) -> Response:
        """POST /tasks"""
        try:
            data = json.loads(body)
            task = Task.from_dict(data)
            created = self._store.create(task)
            return Response(
                status=HTTPStatus.CREATED,
                body=json.dumps(created.to_dict(), indent=2),
            )
        except (json.JSONDecodeError, KeyError) as e:
            return Response(
                status=HTTPStatus.BAD_REQUEST,
                body=json.dumps({"error": str(e)}),
            )
        except ValidationError as e:
            return Response(
                status=HTTPStatus.UNPROCESSABLE_ENTITY,
                body=json.dumps({"error": str(e), "field": e.field}),
            )

    def handle_get(self, task_id: str) -> Response:
        """GET /tasks/{id}"""
        try:
            task = self._store.get(task_id)
            return Response(
                status=HTTPStatus.OK,
                body=json.dumps(task.to_dict(), indent=2),
            )
        except TaskNotFoundError:
            return Response(
                status=HTTPStatus.NOT_FOUND,
                body=json.dumps({"error": f"Task {task_id} not found"}),
            )

    def handle_update(self, task_id: str, body: str) -> Response:
        """PATCH /tasks/{id}"""
        try:
            updates = json.loads(body)
            task = self._store.update(task_id, updates)
            return Response(
                status=HTTPStatus.OK,
                body=json.dumps(task.to_dict(), indent=2),
            )
        except TaskNotFoundError:
            return Response(
                status=HTTPStatus.NOT_FOUND,
                body=json.dumps({"error": f"Task {task_id} not found"}),
            )
        except ValidationError as e:
            return Response(
                status=HTTPStatus.UNPROCESSABLE_ENTITY,
                body=json.dumps({"error": str(e), "field": e.field}),
            )

    def handle_delete(self, task_id: str) -> Response:
        """DELETE /tasks/{id}"""
        try:
            self._store.delete(task_id)
            return Response(status=HTTPStatus.NO_CONTENT, body="")
        except TaskNotFoundError:
            return Response(
                status=HTTPStatus.NOT_FOUND,
                body=json.dumps({"error": f"Task {task_id} not found"}),
            )

    def handle_list(self, status: str | None = None, priority: str | None = None) -> Response:
        """GET /tasks"""
        task_filter = TaskFilter(
            status=TaskStatus(status) if status else None,
            priority=Priority(priority) if priority else None,
        )
        tasks = self._store.list_tasks(task_filter)
        return Response(
            status=HTTPStatus.OK,
            body=json.dumps([t.to_dict() for t in tasks], indent=2),
        )

    def handle_stats(self) -> Response:
        """GET /tasks/stats"""
        return Response(
            status=HTTPStatus.OK,
            body=json.dumps(self._store.stats(), indent=2),
        )


def main() -> None:
    handler = TodoHandler()

    # Create tasks
    tasks_data = [
        {"title": "Write unit tests", "priority": "high", "tags": [{"name": "testing"}]},
        {"title": "Update README", "priority": "low", "assignee": "alice"},
        {"title": "Fix login bug", "priority": "critical", "tags": [{"name": "bug", "color": "#ff0000"}]},
        {"title": "Code review", "priority": "medium", "assignee": "bob"},
    ]

    created_ids: list[str] = []
    for data in tasks_data:
        resp = handler.handle_create(json.dumps(data))
        task = json.loads(resp.body)
        created_ids.append(task["id"])
        print(f"Created: {task['title']} (ID: {task['id'][:8]}...)")

    # List all tasks
    resp = handler.handle_list()
    all_tasks = json.loads(resp.body)
    print(f"\nTotal tasks: {len(all_tasks)}")

    # Update first task
    if created_ids:
        resp = handler.handle_update(
            created_ids[0],
            json.dumps({"status": "in_progress"}),
        )
        print(f"\nUpdated task status: {json.loads(resp.body)['status']}")

    # Get stats
    resp = handler.handle_stats()
    stats = json.loads(resp.body)
    print(f"\nStats: {stats}")

    # Delete last task
    if created_ids:
        resp = handler.handle_delete(created_ids[-1])
        print(f"\nDeleted task: {resp.status}")


if __name__ == "__main__":
    main()
