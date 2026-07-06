"""URL shortener service with analytics.

Covers: hashlib, base64, datetime, defaultdict, Counter,
        dataclass with __post_init__, property, class variables,
        threading Lock, expiration logic, URL validation.
"""

from __future__ import annotations

import hashlib
import re
import threading
import time
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum, auto
from typing import Iterator


class URLError(Exception):
    """Base URL error."""


class InvalidURLError(URLError):
    """Raised for invalid URLs."""


class ExpiredURLError(URLError):
    """Raised when accessing an expired short URL."""


class URLNotFoundError(URLError):
    """Raised when short code doesn't exist."""


URL_PATTERN = re.compile(
    r"^https?://"
    r"(?:[\w-]+\.)+[\w]{2,}"
    r"(?:/[^\s]*)?$"
)


def validate_url(url: str) -> bool:
    """Validate a URL format."""
    return bool(URL_PATTERN.match(url))


class HashAlgorithm(Enum):
    """Hash algorithms for short code generation."""

    MD5 = auto()
    SHA1 = auto()
    SHA256 = auto()


@dataclass
class ShortenedURL:
    """A shortened URL entry with metadata."""

    original_url: str
    short_code: str
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: datetime | None = None
    max_clicks: int | None = None
    custom_alias: str | None = None
    creator: str = ""
    _click_count: int = field(default=0, repr=False)
    _click_times: list[datetime] = field(default_factory=list, repr=False)

    @property
    def click_count(self) -> int:
        return self._click_count

    @property
    def is_expired(self) -> bool:
        if self.expires_at and datetime.now(timezone.utc) > self.expires_at:
            return True
        if self.max_clicks and self._click_count >= self.max_clicks:
            return True
        return False

    @property
    def age_seconds(self) -> float:
        delta = datetime.now(timezone.utc) - self.created_at
        return delta.total_seconds()

    def record_click(self) -> None:
        """Record a click event."""
        self._click_count += 1
        self._click_times.append(datetime.now(timezone.utc))

    def clicks_in_period(self, hours: int = 24) -> int:
        """Count clicks in the last N hours."""
        cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
        return sum(1 for t in self._click_times if t >= cutoff)


class CodeGenerator:
    """Generates short codes from URLs."""

    CHARSET = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

    @classmethod
    def generate(cls, url: str, length: int = 6, algorithm: HashAlgorithm = HashAlgorithm.SHA256) -> str:
        """Generate a short code from a URL."""
        if algorithm == HashAlgorithm.MD5:
            digest = hashlib.md5(url.encode()).hexdigest()
        elif algorithm == HashAlgorithm.SHA1:
            digest = hashlib.sha1(url.encode()).hexdigest()
        else:
            digest = hashlib.sha256(url.encode()).hexdigest()

        # Convert hex digest to base62
        num = int(digest[:16], 16)
        code: list[str] = []
        while num > 0 and len(code) < length:
            code.append(cls.CHARSET[num % len(cls.CHARSET)])
            num //= len(cls.CHARSET)

        return "".join(code).ljust(length, "a")

    @classmethod
    def generate_unique(cls, url: str, existing: set[str], length: int = 6) -> str:
        """Generate a unique code, appending salt on collision."""
        code = cls.generate(url, length)
        salt = 0
        while code in existing:
            salt += 1
            code = cls.generate(f"{url}:{salt}", length)
        return code


class URLStore:
    """Thread-safe in-memory URL store."""

    def __init__(self) -> None:
        self._by_code: dict[str, ShortenedURL] = {}
        self._by_url: dict[str, str] = {}
        self._lock = threading.Lock()

    def __len__(self) -> int:
        with self._lock:
            return len(self._by_code)

    def __contains__(self, code: str) -> bool:
        with self._lock:
            return code in self._by_code

    def __iter__(self) -> Iterator[ShortenedURL]:
        with self._lock:
            yield from list(self._by_code.values())

    def put(self, entry: ShortenedURL) -> None:
        with self._lock:
            self._by_code[entry.short_code] = entry
            self._by_url[entry.original_url] = entry.short_code

    def get(self, code: str) -> ShortenedURL | None:
        with self._lock:
            return self._by_code.get(code)

    def find_by_url(self, url: str) -> str | None:
        with self._lock:
            return self._by_url.get(url)

    def delete(self, code: str) -> bool:
        with self._lock:
            entry = self._by_code.pop(code, None)
            if entry:
                self._by_url.pop(entry.original_url, None)
                return True
            return False

    def cleanup_expired(self) -> int:
        """Remove expired entries. Returns count removed."""
        with self._lock:
            expired = [code for code, entry in self._by_code.items() if entry.is_expired]
            for code in expired:
                entry = self._by_code.pop(code)
                self._by_url.pop(entry.original_url, None)
            return len(expired)


@dataclass
class Analytics:
    """URL click analytics."""

    clicks_by_code: Counter[str] = field(default_factory=Counter)
    clicks_by_hour: defaultdict[int, int] = field(
        default_factory=lambda: defaultdict(int)
    )

    def record(self, code: str) -> None:
        self.clicks_by_code[code] += 1
        hour = datetime.now(timezone.utc).hour
        self.clicks_by_hour[hour] += 1

    def top_urls(self, n: int = 10) -> list[tuple[str, int]]:
        return self.clicks_by_code.most_common(n)

    def total_clicks(self) -> int:
        return sum(self.clicks_by_code.values())

    def busiest_hour(self) -> int | None:
        if not self.clicks_by_hour:
            return None
        return max(self.clicks_by_hour, key=lambda h: self.clicks_by_hour[h])


class URLShortener:
    """Main URL shortener service."""

    BASE_URL: str = "https://short.url/"

    def __init__(self) -> None:
        self.store = URLStore()
        self.analytics = Analytics()
        self._generator = CodeGenerator()

    def shorten(
        self,
        url: str,
        custom_alias: str | None = None,
        expires_in_hours: int | None = None,
        max_clicks: int | None = None,
        creator: str = "",
    ) -> ShortenedURL:
        """Shorten a URL."""
        if not validate_url(url):
            raise InvalidURLError(f"Invalid URL: {url}")

        # Check if already shortened
        if existing_code := self.store.find_by_url(url):
            existing = self.store.get(existing_code)
            if existing and not existing.is_expired:
                return existing

        # Generate or use custom code
        if custom_alias:
            if custom_alias in self.store:
                raise URLError(f"Alias already in use: {custom_alias}")
            code = custom_alias
        else:
            existing_codes = {e.short_code for e in self.store}
            code = self._generator.generate_unique(url, existing_codes)

        expires_at = None
        if expires_in_hours:
            expires_at = datetime.now(timezone.utc) + timedelta(hours=expires_in_hours)

        entry = ShortenedURL(
            original_url=url,
            short_code=code,
            expires_at=expires_at,
            max_clicks=max_clicks,
            custom_alias=custom_alias,
            creator=creator,
        )
        self.store.put(entry)
        return entry

    def resolve(self, code: str) -> str:
        """Resolve a short code to original URL."""
        entry = self.store.get(code)
        if entry is None:
            raise URLNotFoundError(f"Short code not found: {code}")
        if entry.is_expired:
            raise ExpiredURLError(f"Short URL has expired: {code}")
        entry.record_click()
        self.analytics.record(code)
        return entry.original_url

    def short_url(self, code: str) -> str:
        """Get the full short URL."""
        return f"{self.BASE_URL}{code}"

    def info(self, code: str) -> dict:
        """Get info about a shortened URL."""
        entry = self.store.get(code)
        if entry is None:
            raise URLNotFoundError(code)
        return {
            "original_url": entry.original_url,
            "short_url": self.short_url(code),
            "created_at": entry.created_at.isoformat(),
            "clicks": entry.click_count,
            "is_expired": entry.is_expired,
            "creator": entry.creator,
        }
