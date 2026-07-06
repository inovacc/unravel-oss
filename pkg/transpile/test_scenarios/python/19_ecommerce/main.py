"""Entry point demonstrating the e-commerce system end-to-end.

Demonstrates: service orchestration, error handling, formatted output.
"""

from __future__ import annotations

from models import OrderStatus
from services import CatalogService, CustomerService, OrderError, OrderService


def run_demo() -> None:
    # Initialize services with shared dependencies
    catalog = CatalogService()
    customers = CustomerService()
    orders = OrderService(catalog=catalog, customers=customers)

    # Set up catalog
    laptop = catalog.add_product("Laptop Pro 16", 249900, stock=10, tags=["electronics", "computers"])
    mouse = catalog.add_product("Wireless Mouse", 4999, stock=50, tags=["electronics", "accessories"])
    book = catalog.add_product("Clean Code", 3499, stock=25, tags=["books", "programming"])
    headphones = catalog.add_product("Noise Cancelling Headphones", 19999, stock=5, tags=["electronics", "audio"])

    print("=== Catalog ===")
    for product in catalog.repo.find_all():
        status = "In Stock" if product.is_available() else "Out of Stock"
        print(f"  {product.name}: {product.price.display()} ({status}, qty={product.stock})")

    # Register customers
    alice = customers.register("alice@example.com", "Alice Johnson")
    customers.add_address(alice.id, "123 Main St", "Springfield", "IL", "62701")

    bob = customers.register("bob@example.com", "Bob Smith")
    customers.add_address(bob.id, "456 Oak Ave", "Portland", "OR", "97201")

    # Alice places an order
    print("\n=== Alice's Order ===")
    order1 = orders.create_order(alice.id)
    orders.add_to_order(order1.id, laptop.id, 1)
    orders.add_to_order(order1.id, mouse.id, 2)
    orders.confirm_order(order1.id)

    summary = orders.get_order_summary(order1.id)
    print(f"  Order: {summary['id'][:8]}...")
    print(f"  Customer: {summary['customer']}")
    print(f"  Status: {summary['status']}")
    print(f"  Items: {summary['items']}")
    print(f"  Subtotal: {summary['subtotal']}")
    print(f"  Ship to: {summary['shipping']}")

    # Bob places an order then cancels
    print("\n=== Bob's Order (cancelled) ===")
    order2 = orders.create_order(bob.id)
    orders.add_to_order(order2.id, headphones.id, 1)
    orders.add_to_order(order2.id, book.id, 3)
    print(f"  Before cancel: headphones stock={headphones.stock}, book stock={book.stock}")
    orders.cancel_order(order2.id)
    print(f"  After cancel:  headphones stock={headphones.stock}, book stock={book.stock}")
    print(f"  Order status: {order2.status.name}")

    # Search catalog
    print("\n=== Search Results ===")
    results = catalog.search("pro")
    for p in results:
        print(f"  Found: {p.name}")

    electronics = catalog.repo.find_by_tag("electronics")
    print(f"  Electronics: {len(electronics)} products")

    # Error handling demo
    print("\n=== Error Handling ===")
    try:
        orders.add_to_order(order1.id, laptop.id, 1)
    except OrderError as e:
        print(f"  Expected error: {e}")

    try:
        catalog.get_product("nonexistent-id")
    except Exception as e:
        print(f"  Expected error: {e}")

    # Stats
    print("\n=== Stats ===")
    print(f"  Products: {catalog.repo.count()}")
    print(f"  Customers: {customers.repo.count()}")
    print(f"  Orders: {orders.order_repo.count()}")


if __name__ == "__main__":
    run_demo()
