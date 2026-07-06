"""Domain models for the e-commerce system.

Demonstrates: dataclasses, enums, validation, relationships between models.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum, auto
from typing import Optional
from uuid import uuid4


class Currency(Enum):
    USD = "USD"
    EUR = "EUR"
    GBP = "GBP"
    BRL = "BRL"


class OrderStatus(Enum):
    PENDING = auto()
    CONFIRMED = auto()
    SHIPPED = auto()
    DELIVERED = auto()
    CANCELLED = auto()


@dataclass
class Money:
    amount: int  # cents
    currency: Currency = Currency.USD

    def __add__(self, other: Money) -> Money:
        if self.currency != other.currency:
            raise ValueError(f"Cannot add {self.currency.value} and {other.currency.value}")
        return Money(self.amount + other.amount, self.currency)

    def __mul__(self, qty: int) -> Money:
        return Money(self.amount * qty, self.currency)

    def display(self) -> str:
        whole = self.amount // 100
        cents = self.amount % 100
        return f"{self.currency.value} {whole}.{cents:02d}"


@dataclass
class Product:
    id: str = field(default_factory=lambda: str(uuid4()))
    name: str = ""
    description: str = ""
    price: Money = field(default_factory=Money)
    stock: int = 0
    tags: list[str] = field(default_factory=list)

    def is_available(self) -> bool:
        return self.stock > 0

    def reserve(self, qty: int) -> bool:
        if qty > self.stock:
            return False
        self.stock -= qty
        return True

    def release(self, qty: int) -> None:
        self.stock += qty


@dataclass
class Customer:
    id: str = field(default_factory=lambda: str(uuid4()))
    email: str = ""
    name: str = ""
    addresses: list[Address] = field(default_factory=list)

    def primary_address(self) -> Optional[Address]:
        if not self.addresses:
            return None
        return self.addresses[0]


@dataclass
class Address:
    street: str = ""
    city: str = ""
    state: str = ""
    zip_code: str = ""
    country: str = "US"

    def format(self) -> str:
        return f"{self.street}, {self.city}, {self.state} {self.zip_code}, {self.country}"


@dataclass
class OrderItem:
    product: Product
    quantity: int
    unit_price: Money

    def total(self) -> Money:
        return self.unit_price * self.quantity


@dataclass
class Order:
    id: str = field(default_factory=lambda: str(uuid4()))
    customer: Optional[Customer] = None
    items: list[OrderItem] = field(default_factory=list)
    status: OrderStatus = OrderStatus.PENDING
    shipping_address: Optional[Address] = None
    created_at: datetime = field(default_factory=datetime.now)

    def subtotal(self) -> Money:
        if not self.items:
            return Money(0)
        total = Money(0, self.items[0].unit_price.currency)
        for item in self.items:
            total = total + item.total()
        return total

    def add_item(self, product: Product, quantity: int) -> None:
        if not product.reserve(quantity):
            raise ValueError(f"Insufficient stock for {product.name}")
        item = OrderItem(
            product=product,
            quantity=quantity,
            unit_price=product.price,
        )
        self.items.append(item)

    def cancel(self) -> None:
        if self.status in (OrderStatus.SHIPPED, OrderStatus.DELIVERED):
            raise ValueError("Cannot cancel shipped/delivered order")
        for item in self.items:
            item.product.release(item.quantity)
        self.status = OrderStatus.CANCELLED
