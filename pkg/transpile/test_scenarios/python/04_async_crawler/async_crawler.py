"""An async web crawler with rate limiting, queue-based processing, and result collection.

Demonstrates: asyncio, async/await, Semaphore, Queue, async context managers,
              async generators, dataclasses, type hints.
Difficulty: Hard (~350 LOC)
"""

from __future__ import annotations

import asyncio
import hashlib
import html
import re
import time
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import AsyncIterator
from urllib.parse import urljoin, urlparse


class CrawlStatus(Enum):
    PENDING = auto()
    IN_PROGRESS = auto()
    COMPLETED = auto()
    FAILED = auto()
    SKIPPED = auto()


@dataclass
class CrawlResult:
    url: str
    status: CrawlStatus
    status_code: int = 0
    content_length: int = 0
    links_found: int = 0
    elapsed_ms: float = 0.0
    error: str = ""
    content_hash: str = ""
    title: str = ""


@dataclass
class CrawlerConfig:
    max_depth: int = 3
    max_concurrent: int = 10
    max_pages: int = 100
    request_delay: float = 0.1
    timeout: float = 10.0
    allowed_domains: list[str] = field(default_factory=list)
    exclude_patterns: list[str] = field(default_factory=list)
    user_agent: str = "TogoCrawler/1.0"


@dataclass
class CrawlTask:
    url: str
    depth: int
    parent_url: str = ""
    retry_count: int = 0


class RateLimiter:
    """Token-bucket rate limiter for controlling request frequency."""

    def __init__(self, requests_per_second: float = 10.0) -> None:
        self._rate = requests_per_second
        self._tokens = requests_per_second
        self._max_tokens = requests_per_second
        self._last_refill = time.monotonic()
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        """Wait until a token is available."""
        async with self._lock:
            now = time.monotonic()
            elapsed = now - self._last_refill
            self._tokens = min(self._max_tokens, self._tokens + elapsed * self._rate)
            self._last_refill = now

            if self._tokens < 1.0:
                wait_time = (1.0 - self._tokens) / self._rate
                await asyncio.sleep(wait_time)
                self._tokens = 0.0
            else:
                self._tokens -= 1.0


class URLFilter:
    """Filters URLs based on domain and pattern rules."""

    def __init__(self, config: CrawlerConfig) -> None:
        self._allowed_domains = set(config.allowed_domains)
        self._exclude_patterns = [re.compile(p) for p in config.exclude_patterns]

    def is_allowed(self, url: str) -> bool:
        """Check if a URL passes all filter rules."""
        parsed = urlparse(url)

        # Scheme check
        if parsed.scheme not in ("http", "https"):
            return False

        # Domain check
        if self._allowed_domains and parsed.netloc not in self._allowed_domains:
            return False

        # Exclude patterns
        for pattern in self._exclude_patterns:
            if pattern.search(url):
                return False

        # Skip common non-page resources
        path_lower = parsed.path.lower()
        skip_extensions = (".jpg", ".jpeg", ".png", ".gif", ".css", ".js", ".pdf", ".zip")
        if any(path_lower.endswith(ext) for ext in skip_extensions):
            return False

        return True


class ContentParser:
    """Extracts links and metadata from HTML content."""

    _link_re = re.compile(r'<a\s+[^>]*href=["\']([^"\']+)["\']', re.IGNORECASE)
    _title_re = re.compile(r"<title[^>]*>([^<]+)</title>", re.IGNORECASE)

    @staticmethod
    def extract_links(content: str, base_url: str) -> list[str]:
        """Extract and normalize all links from HTML content."""
        links: list[str] = []
        seen: set[str] = set()

        for match in ContentParser._link_re.finditer(content):
            href = html.unescape(match.group(1)).strip()

            # Skip anchors and javascript
            if href.startswith(("#", "javascript:", "mailto:", "tel:")):
                continue

            # Resolve relative URLs
            absolute = urljoin(base_url, href)

            # Remove fragment
            parsed = urlparse(absolute)
            clean = parsed._replace(fragment="").geturl()

            if clean not in seen:
                seen.add(clean)
                links.append(clean)

        return links

    @staticmethod
    def extract_title(content: str) -> str:
        """Extract the page title from HTML content."""
        match = ContentParser._title_re.search(content)
        if match:
            return html.unescape(match.group(1)).strip()
        return ""

    @staticmethod
    def content_hash(content: str) -> str:
        """Compute a hash of the content for deduplication."""
        return hashlib.sha256(content.encode("utf-8")).hexdigest()[:16]


class FakeHTTPClient:
    """Simulated HTTP client for testing without real network access."""

    def __init__(self, pages: dict[str, str], delay: float = 0.01) -> None:
        self._pages = pages
        self._delay = delay

    async def get(self, url: str, timeout: float = 10.0) -> tuple[int, str]:
        """Simulate an HTTP GET request."""
        await asyncio.sleep(self._delay)

        if url in self._pages:
            return 200, self._pages[url]

        return 404, "<html><body>Not Found</body></html>"


class CrawlStats:
    """Thread-safe statistics collector for the crawl."""

    def __init__(self) -> None:
        self._results: list[CrawlResult] = []
        self._lock = asyncio.Lock()
        self._start_time = time.monotonic()

    async def add_result(self, result: CrawlResult) -> None:
        async with self._lock:
            self._results.append(result)

    async def get_results(self) -> list[CrawlResult]:
        async with self._lock:
            return list(self._results)

    async def summary(self) -> dict[str, int | float]:
        async with self._lock:
            elapsed = time.monotonic() - self._start_time
            status_counts: dict[str, int] = {}
            total_links = 0

            for r in self._results:
                key = r.status.name
                status_counts[key] = status_counts.get(key, 0) + 1
                total_links += r.links_found

            return {
                "total_pages": len(self._results),
                "total_links": total_links,
                "elapsed_seconds": round(elapsed, 3),
                **status_counts,
            }


class AsyncCrawler:
    """Async web crawler with bounded concurrency and depth control."""

    def __init__(self, config: CrawlerConfig, client: FakeHTTPClient) -> None:
        self._config = config
        self._client = client
        self._url_filter = URLFilter(config)
        self._rate_limiter = RateLimiter(1.0 / config.request_delay if config.request_delay > 0 else 100.0)
        self._semaphore = asyncio.Semaphore(config.max_concurrent)
        self._visited: set[str] = set()
        self._visited_lock = asyncio.Lock()
        self._stats = CrawlStats()
        self._queue: asyncio.Queue[CrawlTask] = asyncio.Queue()

    async def crawl(self, start_urls: list[str]) -> list[CrawlResult]:
        """Start crawling from the given seed URLs."""
        for url in start_urls:
            await self._queue.put(CrawlTask(url=url, depth=0))

        workers = [
            asyncio.create_task(self._worker(i))
            for i in range(self._config.max_concurrent)
        ]

        await self._queue.join()

        for worker in workers:
            worker.cancel()

        await asyncio.gather(*workers, return_exceptions=True)

        return await self._stats.get_results()

    async def _worker(self, worker_id: int) -> None:
        """Worker coroutine that processes crawl tasks from the queue."""
        while True:
            try:
                task = await asyncio.wait_for(self._queue.get(), timeout=2.0)
            except asyncio.TimeoutError:
                continue
            except asyncio.CancelledError:
                return

            try:
                await self._process_task(task, worker_id)
            except Exception as e:
                result = CrawlResult(
                    url=task.url,
                    status=CrawlStatus.FAILED,
                    error=str(e),
                )
                await self._stats.add_result(result)
            finally:
                self._queue.task_done()

    async def _process_task(self, task: CrawlTask, worker_id: int) -> None:
        """Process a single crawl task."""
        # Check if already visited
        async with self._visited_lock:
            if task.url in self._visited:
                return
            if len(self._visited) >= self._config.max_pages:
                return
            self._visited.add(task.url)

        # Check URL filter
        if not self._url_filter.is_allowed(task.url):
            result = CrawlResult(url=task.url, status=CrawlStatus.SKIPPED)
            await self._stats.add_result(result)
            return

        # Rate limit
        await self._rate_limiter.acquire()

        # Fetch with semaphore
        async with self._semaphore:
            start = time.monotonic()

            try:
                status_code, content = await self._client.get(
                    task.url, timeout=self._config.timeout,
                )
            except Exception as e:
                result = CrawlResult(
                    url=task.url,
                    status=CrawlStatus.FAILED,
                    error=str(e),
                    elapsed_ms=(time.monotonic() - start) * 1000,
                )
                await self._stats.add_result(result)
                return

            elapsed_ms = (time.monotonic() - start) * 1000

        # Parse content
        links = ContentParser.extract_links(content, task.url)
        title = ContentParser.extract_title(content)
        content_h = ContentParser.content_hash(content)

        result = CrawlResult(
            url=task.url,
            status=CrawlStatus.COMPLETED,
            status_code=status_code,
            content_length=len(content),
            links_found=len(links),
            elapsed_ms=elapsed_ms,
            content_hash=content_h,
            title=title,
        )
        await self._stats.add_result(result)

        # Enqueue child links
        if task.depth < self._config.max_depth and status_code == 200:
            for link in links:
                async with self._visited_lock:
                    if link not in self._visited and len(self._visited) < self._config.max_pages:
                        await self._queue.put(CrawlTask(
                            url=link,
                            depth=task.depth + 1,
                            parent_url=task.url,
                        ))

    async def stream_results(self) -> AsyncIterator[CrawlResult]:
        """Async generator that yields results as they become available."""
        results = await self._stats.get_results()
        for result in results:
            yield result


async def main() -> None:
    # Build a simulated website
    pages: dict[str, str] = {
        "https://example.com/": """<html><title>Home</title><body>
            <a href="/about">About</a>
            <a href="/blog">Blog</a>
            <a href="/contact">Contact</a>
        </body></html>""",
        "https://example.com/about": """<html><title>About Us</title><body>
            <a href="/">Home</a>
            <a href="/team">Team</a>
        </body></html>""",
        "https://example.com/blog": """<html><title>Blog</title><body>
            <a href="/blog/post-1">Post 1</a>
            <a href="/blog/post-2">Post 2</a>
            <a href="/">Home</a>
        </body></html>""",
        "https://example.com/blog/post-1": """<html><title>Blog Post 1</title><body>
            <a href="/blog">Back to Blog</a>
            <a href="/blog/post-2">Next Post</a>
        </body></html>""",
        "https://example.com/blog/post-2": """<html><title>Blog Post 2</title><body>
            <a href="/blog">Back to Blog</a>
            <a href="/blog/post-1">Previous Post</a>
        </body></html>""",
        "https://example.com/contact": """<html><title>Contact</title><body>
            <a href="/">Home</a>
            <a href="mailto:test@example.com">Email</a>
        </body></html>""",
        "https://example.com/team": """<html><title>Team</title><body>
            <a href="/about">About</a>
        </body></html>""",
    }

    config = CrawlerConfig(
        max_depth=2,
        max_concurrent=3,
        max_pages=20,
        request_delay=0.01,
        allowed_domains=["example.com"],
        exclude_patterns=[r"\.pdf$", r"\.zip$"],
    )

    client = FakeHTTPClient(pages)
    crawler = AsyncCrawler(config, client)

    print("Starting crawl...")
    results = await crawler.crawl(["https://example.com/"])

    print(f"\nCrawl Results ({len(results)} pages):")
    print("-" * 70)

    for result in sorted(results, key=lambda r: r.url):
        status_icon = {
            CrawlStatus.COMPLETED: "+",
            CrawlStatus.FAILED: "!",
            CrawlStatus.SKIPPED: "-",
        }.get(result.status, "?")

        print(
            f"  [{status_icon}] {result.url}"
            f" ({result.status_code}, {result.content_length}B,"
            f" {result.links_found} links, {result.elapsed_ms:.1f}ms)"
        )
        if result.title:
            print(f"      Title: {result.title}")

    summary = await crawler._stats.summary()
    print(f"\nSummary: {summary}")


if __name__ == "__main__":
    asyncio.run(main())
