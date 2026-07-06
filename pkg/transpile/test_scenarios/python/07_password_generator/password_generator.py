"""Secure password generator with strength analysis.

Covers: string module, secrets, itertools, properties, slots,
        class methods, static methods, generator expressions.
"""

from __future__ import annotations

import hashlib
import secrets
import string
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Iterator


class Strength(IntEnum):
    """Password strength levels."""

    WEAK = 1
    FAIR = 2
    STRONG = 3
    VERY_STRONG = 4


@dataclass(slots=True)
class PasswordPolicy:
    """Configurable password generation policy."""

    length: int = 16
    use_upper: bool = True
    use_lower: bool = True
    use_digits: bool = True
    use_symbols: bool = True
    exclude_chars: str = ""
    min_upper: int = 1
    min_lower: int = 1
    min_digits: int = 1
    min_symbols: int = 0

    def __post_init__(self) -> None:
        if self.length < 4:
            raise ValueError("Password length must be at least 4")

    @property
    def charset(self) -> str:
        """Build character set from policy."""
        chars = ""
        if self.use_upper:
            chars += string.ascii_uppercase
        if self.use_lower:
            chars += string.ascii_lowercase
        if self.use_digits:
            chars += string.digits
        if self.use_symbols:
            chars += string.punctuation
        return "".join(c for c in chars if c not in self.exclude_chars)


class PasswordGenerator:
    """Generates secure passwords using secrets module."""

    def __init__(self, policy: PasswordPolicy | None = None) -> None:
        self._policy = policy or PasswordPolicy()
        self._history: list[str] = []

    @property
    def policy(self) -> PasswordPolicy:
        return self._policy

    @policy.setter
    def policy(self, value: PasswordPolicy) -> None:
        self._policy = value

    def generate(self) -> str:
        """Generate a single password meeting the policy."""
        charset = self._policy.charset
        if not charset:
            raise ValueError("Empty character set")

        while True:
            password = "".join(
                secrets.choice(charset) for _ in range(self._policy.length)
            )
            if self._meets_requirements(password):
                self._history.append(password)
                return password

    def generate_batch(self, count: int) -> list[str]:
        """Generate multiple unique passwords."""
        passwords: set[str] = set()
        while len(passwords) < count:
            passwords.add(self.generate())
        return sorted(passwords)

    def _meets_requirements(self, password: str) -> bool:
        """Check if password meets minimum character requirements."""
        p = self._policy
        upper_count = sum(1 for c in password if c in string.ascii_uppercase)
        lower_count = sum(1 for c in password if c in string.ascii_lowercase)
        digit_count = sum(1 for c in password if c in string.digits)
        symbol_count = sum(1 for c in password if c in string.punctuation)

        return (
            upper_count >= p.min_upper
            and lower_count >= p.min_lower
            and digit_count >= p.min_digits
            and symbol_count >= p.min_symbols
        )


class StrengthAnalyzer:
    """Analyzes password strength."""

    COMMON_PATTERNS: list[str] = [
        "password", "123456", "qwerty", "abc123", "letmein",
    ]

    @staticmethod
    def entropy(password: str) -> float:
        """Calculate Shannon entropy of password."""
        if not password:
            return 0.0
        freq: dict[str, int] = {}
        for ch in password:
            freq[ch] = freq.get(ch, 0) + 1
        length = len(password)
        import math
        return -sum(
            (count / length) * math.log2(count / length)
            for count in freq.values()
        )

    @classmethod
    def analyze(cls, password: str) -> Strength:
        """Determine password strength."""
        if len(password) < 6:
            return Strength.WEAK

        lower_pw = password.lower()
        if any(pattern in lower_pw for pattern in cls.COMMON_PATTERNS):
            return Strength.WEAK

        score = 0
        if len(password) >= 8:
            score += 1
        if len(password) >= 12:
            score += 1
        if any(c in string.ascii_uppercase for c in password):
            score += 1
        if any(c in string.digits for c in password):
            score += 1
        if any(c in string.punctuation for c in password):
            score += 1
        if cls.entropy(password) > 3.0:
            score += 1

        if score <= 2:
            return Strength.FAIR
        if score <= 4:
            return Strength.STRONG
        return Strength.VERY_STRONG

    @staticmethod
    def sha256_hash(password: str) -> str:
        """Hash password with SHA-256."""
        return hashlib.sha256(password.encode()).hexdigest()


@dataclass
class PasswordEntry:
    """Stored password entry."""

    label: str
    password: str
    strength: Strength
    hash: str = field(init=False)

    def __post_init__(self) -> None:
        self.hash = StrengthAnalyzer.sha256_hash(self.password)


class PasswordVault:
    """In-memory password vault with iteration support."""

    def __init__(self) -> None:
        self._entries: dict[str, PasswordEntry] = {}

    def __len__(self) -> int:
        return len(self._entries)

    def __contains__(self, label: str) -> bool:
        return label in self._entries

    def __iter__(self) -> Iterator[PasswordEntry]:
        yield from self._entries.values()

    def add(self, label: str, password: str) -> PasswordEntry:
        """Add a password entry."""
        strength = StrengthAnalyzer.analyze(password)
        entry = PasswordEntry(label=label, password=password, strength=strength)
        self._entries[label] = entry
        return entry

    def get(self, label: str) -> PasswordEntry | None:
        """Retrieve a password entry."""
        return self._entries.get(label)

    def remove(self, label: str) -> bool:
        """Remove a password entry."""
        if label in self._entries:
            del self._entries[label]
            return True
        return False

    def search(self, query: str) -> list[PasswordEntry]:
        """Search entries by label substring."""
        return [
            entry for entry in self._entries.values()
            if query.lower() in entry.label.lower()
        ]

    def weak_passwords(self) -> list[PasswordEntry]:
        """Find all entries with weak passwords."""
        return [e for e in self if e.strength <= Strength.FAIR]
