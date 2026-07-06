"""In-memory repository layer with generic CRUD and query support.

Demonstrates: generics (TypeVar), ABC, dict-based storage, filtering.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Generic, Optional, TypeVar

from models import Customer, Order, Product

T = TypeVar("T")


class Repository(ABC, Generic[T]):
    """Abstract repository interface."""

    @abstractmethod
    def save(self, entity: T) -> None: ...

    @abstractmethod
    def find_by_id(self, id: str) -> Optional[T]: ...

    @abstractmethod
    def find_all(self) -> list[T]: ...

    @abstractmethod
    def delete(self, id: str) -> bool: ...


class InMemoryRepository(Repository[T]):
    """Generic in-memory repository backed by a dict."""

    def __init__(self) -> None:
        self._store: dict[str, T] = {}

    def save(self, entity: T) -> None:
        self._store[entity.id] = entity

    def find_by_id(self, id: str) -> Optional[T]:
        return self._store.get(id)

    def find_all(self) -> list[T]:
        return list(self._store.values())

    def delete(self, id: str) -> bool:
        if id in self._store:
            del self._store[id]
            return True
        return False

    def count(self) -> int:
        return len(self._store)


class ProductRepository(InMemoryRepository[Product]):
    """Product-specific repository with search capabilities."""

    def find_by_tag(self, tag: str) -> list[Product]:
        return [p for p in self._store.values() if tag in p.tags]

    def find_available(self) -> list[Product]:
        return [p for p in self._store.values() if p.is_available()]

    def find_by_name(self, name: str) -> list[Product]:
        query = name.lower()
        return [p for p in self._store.values() if query in p.name.lower()]


class CustomerRepository(InMemoryRepository[Customer]):
    """Customer-specific repository with email lookup."""

    def find_by_email(self, email: str) -> Optional[Customer]:
        for c in self._store.values():
            if c.email == email:
                return c
        return None


class OrderRepository(InMemoryRepository[Order]):
    """Order-specific repository with status/customer queries."""

    def find_by_customer(self, customer_id: str) -> list[Order]:
        return [o for o in self._store.values() if o.customer and o.customer.id == customer_id]

    def find_by_status(self, status: "OrderStatus") -> list[Order]:
        return [o for o in self._store.values() if o.status == status]
