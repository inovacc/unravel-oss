"""Web scraping framework with rate limiting and result extraction.

Covers: urllib.parse, re advanced patterns, queue.Queue,
        threading, robots.txt parsing, retry with backoff,
        dataclass inheritance, set operations, deque.
"""

from __future__ import annotations

import hashlib
import re
import time
import threading
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum, auto
from typing import Callable, Iterator
from urllib.parse import urljoin, urlparse, urlunparse


class RequestMethod(Enum):
    GET = auto()
    HEAD = auto()


class FetchStatus(Enum):
    SUCCESS = "success"
    ERROR = "error"
    TIMEOUT = "timeout"
    BLOCKED = "blocked"
    SKIPPED = "skipped"


@dataclass
class URL:
    """Parsed and normalized URL."""

    raw: str
    scheme: str = ""
    host: str = ""
    path: str = ""
    query: str = ""
    fragment: str = ""

    def __post_init__(self) -> None:
        parsed = urlparse(self.raw)
        self.scheme = parsed.scheme or "https"
        self.host = parsed.netloc
        self.path = parsed.path or "/"
        self.query = parsed.query
        self.fragment = parsed.fragment

    @property
    def domain(self) -> str:
        """Extract domain without port."""
        return self.host.split(":")[0]

    @property
    def normalized(self) -> str:
        """Return normalized URL without fragment."""
        return urlunparse((self.scheme, self.host, self.path, "", self.query, ""))

    @property
    def content_hash(self) -> str:
        return hashlib.md5(self.normalized.encode()).hexdigest()[:12]

    def resolve(self, relative: str) -> URL:
        """Resolve a relative URL against this base."""
        absolute = urljoin(self.normalized, relative)
        return URL(raw=absolute)

    def same_domain(self, other: URL) -> bool:
        return self.domain == other.domain

    def __hash__(self) -> int:
        return hash(self.normalized)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, URL):
            return NotImplemented
        return self.normalized == other.normalized

    def __str__(self) -> str:
        return self.normalized


@dataclass
class FetchResult:
    """Result of fetching a URL."""

    url: URL
    status: FetchStatus
    status_code: int = 0
    content: str = ""
    headers: dict[str, str] = field(default_factory=dict)
    duration_ms: int = 0
    fetched_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    error: str = ""

    @property
    def content_length(self) -> int:
        return len(self.content)

    @property
    def is_html(self) -> bool:
        content_type = self.headers.get("content-type", "")
        return "text/html" in content_type


@dataclass
class ExtractedLink:
    """A link extracted from a page."""

    url: URL
    text: str
    source_url: URL
    is_external: bool = False


class LinkExtractor:
    """Extract links from HTML content."""

    HREF_PATTERN = re.compile(
        r'<a\s+[^>]*href\s*=\s*["\']([^"\']+)["\'][^>]*>(.*?)</a>',
        re.IGNORECASE | re.DOTALL,
    )
    TAG_PATTERN = re.compile(r'<[^>]+>')

    @classmethod
    def extract(cls, content: str, base_url: URL) -> list[ExtractedLink]:
        """Extract all links from HTML content."""
        links: list[ExtractedLink] = []
        seen: set[str] = set()

        for match in cls.HREF_PATTERN.finditer(content):
            href = match.group(1).strip()
            text = cls.TAG_PATTERN.sub("", match.group(2)).strip()

            if href.startswith(("javascript:", "mailto:", "tel:", "#")):
                continue

            resolved = base_url.resolve(href)
            if resolved.normalized in seen:
                continue
            seen.add(resolved.normalized)

            links.append(ExtractedLink(
                url=resolved,
                text=text,
                source_url=base_url,
                is_external=not base_url.same_domain(resolved),
            ))

        return links

    @classmethod
    def extract_text(cls, html: str) -> str:
        """Strip HTML tags and return plain text."""
        text = cls.TAG_PATTERN.sub(" ", html)
        text = re.sub(r'\s+', ' ', text)
        return text.strip()


class MetadataExtractor:
    """Extract metadata from HTML pages."""

    TITLE_PATTERN = re.compile(r'<title[^>]*>(.*?)</title>', re.IGNORECASE | re.DOTALL)
    META_PATTERN = re.compile(
        r'<meta\s+(?:name|property)\s*=\s*["\']([^"\']+)["\']'
        r'\s+content\s*=\s*["\']([^"\']+)["\']',
        re.IGNORECASE,
    )

    @classmethod
    def extract_title(cls, html: str) -> str:
        match = cls.TITLE_PATTERN.search(html)
        return match.group(1).strip() if match else ""

    @classmethod
    def extract_meta(cls, html: str) -> dict[str, str]:
        return {
            match.group(1): match.group(2)
            for match in cls.META_PATTERN.finditer(html)
        }


@dataclass
class RobotRules:
    """Simplified robots.txt rules for a single user-agent."""

    disallowed: list[str] = field(default_factory=list)
    allowed: list[str] = field(default_factory=list)
    crawl_delay: float = 0.0

    def is_allowed(self, path: str) -> bool:
        """Check if a path is allowed."""
        for pattern in self.allowed:
            if path.startswith(pattern):
                return True
        for pattern in self.disallowed:
            if path.startswith(pattern):
                return False
        return True

    @classmethod
    def parse(cls, content: str, user_agent: str = "*") -> RobotRules:
        """Parse robots.txt content."""
        rules = cls()
        current_agent = ""
        for line in content.splitlines():
            line = line.split("#")[0].strip()
            if not line:
                continue
            if line.lower().startswith("user-agent:"):
                current_agent = line.split(":", 1)[1].strip()
            elif current_agent == user_agent or current_agent == "*":
                if line.lower().startswith("disallow:"):
                    path = line.split(":", 1)[1].strip()
                    if path:
                        rules.disallowed.append(path)
                elif line.lower().startswith("allow:"):
                    path = line.split(":", 1)[1].strip()
                    if path:
                        rules.allowed.append(path)
                elif line.lower().startswith("crawl-delay:"):
                    try:
                        rules.crawl_delay = float(line.split(":", 1)[1].strip())
                    except ValueError:
                        pass
        return rules


class RateLimiter:
    """Token bucket rate limiter."""

    def __init__(self, requests_per_second: float = 1.0) -> None:
        self._interval = 1.0 / requests_per_second
        self._last_request: float = 0.0
        self._lock = threading.Lock()

    def acquire(self) -> float:
        """Wait until a request is allowed. Returns wait time in seconds."""
        with self._lock:
            now = time.monotonic()
            elapsed = now - self._last_request
            if elapsed < self._interval:
                wait = self._interval - elapsed
                time.sleep(wait)
                self._last_request = time.monotonic()
                return wait
            self._last_request = now
            return 0.0


@dataclass
class CrawlStats:
    """Statistics for a crawl session."""

    pages_fetched: int = 0
    pages_skipped: int = 0
    pages_failed: int = 0
    links_found: int = 0
    bytes_downloaded: int = 0
    start_time: float = field(default_factory=time.monotonic)

    @property
    def elapsed_seconds(self) -> float:
        return time.monotonic() - self.start_time

    @property
    def pages_per_second(self) -> float:
        elapsed = self.elapsed_seconds
        if elapsed == 0:
            return 0.0
        return self.pages_fetched / elapsed

    def format(self) -> str:
        return (
            f"Fetched: {self.pages_fetched} | "
            f"Skipped: {self.pages_skipped} | "
            f"Failed: {self.pages_failed} | "
            f"Links: {self.links_found} | "
            f"Bytes: {self.bytes_downloaded} | "
            f"Speed: {self.pages_per_second:.1f} p/s"
        )


class CrawlFrontier:
    """BFS frontier with dedup and depth tracking."""

    def __init__(self, max_depth: int = 3) -> None:
        self._queue: deque[tuple[URL, int]] = deque()
        self._seen: set[str] = set()
        self._max_depth = max_depth

    def add(self, url: URL, depth: int = 0) -> bool:
        """Add URL to frontier. Returns True if added (not seen before)."""
        key = url.normalized
        if key in self._seen:
            return False
        if depth > self._max_depth:
            return False
        self._seen.add(key)
        self._queue.append((url, depth))
        return True

    def pop(self) -> tuple[URL, int] | None:
        """Get next URL from frontier."""
        if self._queue:
            return self._queue.popleft()
        return None

    def __len__(self) -> int:
        return len(self._queue)

    @property
    def seen_count(self) -> int:
        return len(self._seen)

    def has_seen(self, url: URL) -> bool:
        return url.normalized in self._seen
