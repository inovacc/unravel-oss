"""Address book with file I/O and search.

Covers: file I/O (open/read/write), csv module, __eq__/__hash__,
        __getitem__/__setitem__, operator overloading, functools,
        re module, os.path, try/except/finally, with statement.
"""

from __future__ import annotations

import csv
import io
import json
import os
import re
from dataclasses import dataclass, field
from enum import Enum, auto
from functools import total_ordering
from typing import Iterator, TextIO


class ContactType(Enum):
    """Types of contacts."""

    PERSONAL = auto()
    WORK = auto()
    FAMILY = auto()
    OTHER = auto()


@total_ordering
@dataclass
class Contact:
    """A contact entry in the address book."""

    first_name: str
    last_name: str
    email: str = ""
    phone: str = ""
    address: str = ""
    contact_type: ContactType = ContactType.PERSONAL
    tags: list[str] = field(default_factory=list)
    notes: str = ""

    @property
    def full_name(self) -> str:
        return f"{self.first_name} {self.last_name}".strip()

    @property
    def sort_key(self) -> str:
        return f"{self.last_name},{self.first_name}".lower()

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Contact):
            return NotImplemented
        return self.email == other.email and self.full_name == other.full_name

    def __hash__(self) -> int:
        return hash((self.full_name, self.email))

    def __lt__(self, other: Contact) -> bool:
        return self.sort_key < other.sort_key

    def __str__(self) -> str:
        parts = [self.full_name]
        if self.email:
            parts.append(f"<{self.email}>")
        if self.phone:
            parts.append(self.phone)
        return " | ".join(parts)

    def matches(self, query: str) -> bool:
        """Check if contact matches a search query."""
        q = query.lower()
        return (
            q in self.first_name.lower()
            or q in self.last_name.lower()
            or q in self.email.lower()
            or q in self.phone
            or q in self.address.lower()
            or any(q in tag.lower() for tag in self.tags)
        )


EMAIL_PATTERN = re.compile(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$")
PHONE_PATTERN = re.compile(r"^\+?[\d\s\-().]{7,20}$")


def validate_email(email: str) -> bool:
    """Validate email format."""
    return bool(EMAIL_PATTERN.match(email))


def validate_phone(phone: str) -> bool:
    """Validate phone number format."""
    return bool(PHONE_PATTERN.match(phone))


class DuplicateContactError(Exception):
    """Raised when adding a duplicate contact."""

    def __init__(self, contact: Contact) -> None:
        self.contact = contact
        super().__init__(f"Contact already exists: {contact.full_name}")


class AddressBook:
    """Address book with search, sort, and file I/O."""

    def __init__(self) -> None:
        self._contacts: dict[str, Contact] = {}

    def __len__(self) -> int:
        return len(self._contacts)

    def __contains__(self, name: str) -> bool:
        return name.lower() in self._contacts

    def __getitem__(self, name: str) -> Contact:
        key = name.lower()
        if key not in self._contacts:
            raise KeyError(f"Contact not found: {name}")
        return self._contacts[key]

    def __setitem__(self, name: str, contact: Contact) -> None:
        self._contacts[name.lower()] = contact

    def __iter__(self) -> Iterator[Contact]:
        yield from sorted(self._contacts.values())

    def add(self, contact: Contact, allow_duplicate: bool = False) -> None:
        """Add a contact to the address book."""
        key = contact.full_name.lower()
        if not allow_duplicate and key in self._contacts:
            raise DuplicateContactError(contact)
        if contact.email and not validate_email(contact.email):
            raise ValueError(f"Invalid email: {contact.email}")
        if contact.phone and not validate_phone(contact.phone):
            raise ValueError(f"Invalid phone: {contact.phone}")
        self._contacts[key] = contact

    def remove(self, name: str) -> bool:
        """Remove a contact by name."""
        key = name.lower()
        if key in self._contacts:
            del self._contacts[key]
            return True
        return False

    def search(self, query: str) -> list[Contact]:
        """Search contacts by any field."""
        return sorted(c for c in self._contacts.values() if c.matches(query))

    def by_type(self, contact_type: ContactType) -> list[Contact]:
        """Filter contacts by type."""
        return sorted(
            c for c in self._contacts.values()
            if c.contact_type == contact_type
        )

    def by_tag(self, tag: str) -> list[Contact]:
        """Filter contacts by tag."""
        return sorted(
            c for c in self._contacts.values()
            if tag.lower() in [t.lower() for t in c.tags]
        )

    def all_tags(self) -> list[str]:
        """Get all unique tags."""
        tags: set[str] = set()
        for c in self._contacts.values():
            tags.update(c.tags)
        return sorted(tags)

    def merge(self, other: AddressBook) -> int:
        """Merge another address book. Returns count of added contacts."""
        added = 0
        for contact in other:
            key = contact.full_name.lower()
            if key not in self._contacts:
                self._contacts[key] = contact
                added += 1
        return added


class CSVExporter:
    """Export/import address book as CSV."""

    FIELDS = ["first_name", "last_name", "email", "phone", "address", "type", "tags"]

    @classmethod
    def export(cls, book: AddressBook, writer: TextIO) -> int:
        """Export address book to CSV. Returns row count."""
        csv_writer = csv.DictWriter(writer, fieldnames=cls.FIELDS)
        csv_writer.writeheader()
        count = 0
        for contact in book:
            csv_writer.writerow({
                "first_name": contact.first_name,
                "last_name": contact.last_name,
                "email": contact.email,
                "phone": contact.phone,
                "address": contact.address,
                "type": contact.contact_type.name,
                "tags": ";".join(contact.tags),
            })
            count += 1
        return count

    @classmethod
    def import_from(cls, reader: TextIO) -> AddressBook:
        """Import address book from CSV."""
        book = AddressBook()
        csv_reader = csv.DictReader(reader)
        for row in csv_reader:
            contact_type = ContactType[row.get("type", "PERSONAL")]
            tags = [t.strip() for t in row.get("tags", "").split(";") if t.strip()]
            contact = Contact(
                first_name=row["first_name"],
                last_name=row["last_name"],
                email=row.get("email", ""),
                phone=row.get("phone", ""),
                address=row.get("address", ""),
                contact_type=contact_type,
                tags=tags,
            )
            try:
                book.add(contact)
            except (DuplicateContactError, ValueError):
                continue
        return book

    @classmethod
    def export_to_string(cls, book: AddressBook) -> str:
        """Export to CSV string."""
        buf = io.StringIO()
        cls.export(book, buf)
        return buf.getvalue()


class JSONExporter:
    """Export/import address book as JSON."""

    @staticmethod
    def export(book: AddressBook) -> str:
        """Export address book to JSON string."""
        contacts = []
        for c in book:
            contacts.append({
                "first_name": c.first_name,
                "last_name": c.last_name,
                "email": c.email,
                "phone": c.phone,
                "address": c.address,
                "type": c.contact_type.name,
                "tags": c.tags,
                "notes": c.notes,
            })
        return json.dumps({"contacts": contacts}, indent=2)

    @staticmethod
    def import_from(data: str) -> AddressBook:
        """Import address book from JSON string."""
        parsed = json.loads(data)
        book = AddressBook()
        for entry in parsed.get("contacts", []):
            contact = Contact(
                first_name=entry["first_name"],
                last_name=entry["last_name"],
                email=entry.get("email", ""),
                phone=entry.get("phone", ""),
                address=entry.get("address", ""),
                contact_type=ContactType[entry.get("type", "PERSONAL")],
                tags=entry.get("tags", []),
                notes=entry.get("notes", ""),
            )
            try:
                book.add(contact)
            except (DuplicateContactError, ValueError):
                continue
        return book


class FileStorage:
    """Persistent file storage for address book."""

    def __init__(self, filepath: str) -> None:
        self.filepath = filepath

    def save(self, book: AddressBook) -> None:
        """Save address book to file."""
        data = JSONExporter.export(book)
        tmp_path = self.filepath + ".tmp"
        try:
            with open(tmp_path, "w", encoding="utf-8") as f:
                f.write(data)
            if os.path.exists(self.filepath):
                os.remove(self.filepath)
            os.rename(tmp_path, self.filepath)
        except OSError:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)
            raise

    def load(self) -> AddressBook:
        """Load address book from file."""
        if not os.path.exists(self.filepath):
            return AddressBook()
        with open(self.filepath, "r", encoding="utf-8") as f:
            data = f.read()
        return JSONExporter.import_from(data)
