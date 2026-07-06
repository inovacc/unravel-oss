"""Business logic services that orchestrate domain operations.

Demonstrates: dependency injection, error handling, service layer pattern.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from models import (
    Address,
    Customer,
    Money,
    Order,
    OrderStatus,
    Product,
)
from repository import CustomerRepository, OrderRepository, ProductRepository


class ServiceError(Exception):
    """Base error for service layer."""

    pass


class ProductNotFoundError(ServiceError):
    pass


class CustomerNotFoundError(ServiceError):
    pass


class OrderError(ServiceError):
    pass


@dataclass
class CatalogService:
    """Manages product catalog operations."""

    repo: ProductRepository = field(default_factory=ProductRepository)

    def add_product(self, name: str, price_cents: int, stock: int, tags: list[str] | None = None) -> Product:
        product = Product(
            name=name,
            price=Money(price_cents),
            stock=stock,
            tags=tags or [],
        )
        self.repo.save(product)
        return product

    def search(self, query: str) -> list[Product]:
        return self.repo.find_by_name(query)

    def get_product(self, product_id: str) -> Product:
        product = self.repo.find_by_id(product_id)
        if product is None:
            raise ProductNotFoundError(f"Product {product_id} not found")
        return product

    def restock(self, product_id: str, quantity: int) -> Product:
        product = self.get_product(product_id)
        product.release(quantity)
        self.repo.save(product)
        return product


@dataclass
class CustomerService:
    """Manages customer operations."""

    repo: CustomerRepository = field(default_factory=CustomerRepository)

    def register(self, email: str, name: str) -> Customer:
        existing = self.repo.find_by_email(email)
        if existing is not None:
            raise ServiceError(f"Email {email} already registered")
        customer = Customer(email=email, name=name)
        self.repo.save(customer)
        return customer

    def add_address(self, customer_id: str, street: str, city: str, state: str, zip_code: str) -> Customer:
        customer = self.repo.find_by_id(customer_id)
        if customer is None:
            raise CustomerNotFoundError(f"Customer {customer_id} not found")
        addr = Address(street=street, city=city, state=state, zip_code=zip_code)
        customer.addresses.append(addr)
        self.repo.save(customer)
        return customer

    def get_customer(self, customer_id: str) -> Customer:
        customer = self.repo.find_by_id(customer_id)
        if customer is None:
            raise CustomerNotFoundError(f"Customer {customer_id} not found")
        return customer


@dataclass
class OrderService:
    """Manages order lifecycle."""

    order_repo: OrderRepository = field(default_factory=OrderRepository)
    catalog: CatalogService = field(default_factory=CatalogService)
    customers: CustomerService = field(default_factory=CustomerService)

    def create_order(self, customer_id: str) -> Order:
        customer = self.customers.get_customer(customer_id)
        order = Order(customer=customer, shipping_address=customer.primary_address())
        self.order_repo.save(order)
        return order

    def add_to_order(self, order_id: str, product_id: str, quantity: int) -> Order:
        order = self._get_order(order_id)
        if order.status != OrderStatus.PENDING:
            raise OrderError("Can only add items to pending orders")
        product = self.catalog.get_product(product_id)
        order.add_item(product, quantity)
        self.order_repo.save(order)
        return order

    def confirm_order(self, order_id: str) -> Order:
        order = self._get_order(order_id)
        if order.status != OrderStatus.PENDING:
            raise OrderError("Only pending orders can be confirmed")
        if not order.items:
            raise OrderError("Cannot confirm empty order")
        order.status = OrderStatus.CONFIRMED
        self.order_repo.save(order)
        return order

    def cancel_order(self, order_id: str) -> Order:
        order = self._get_order(order_id)
        order.cancel()
        self.order_repo.save(order)
        return order

    def get_order_summary(self, order_id: str) -> dict:
        order = self._get_order(order_id)
        return {
            "id": order.id,
            "customer": order.customer.name if order.customer else "Unknown",
            "status": order.status.name,
            "items": len(order.items),
            "subtotal": order.subtotal().display(),
            "shipping": order.shipping_address.format() if order.shipping_address else "No address",
        }

    def _get_order(self, order_id: str) -> Order:
        order = self.order_repo.find_by_id(order_id)
        if order is None:
            raise OrderError(f"Order {order_id} not found")
        return order
