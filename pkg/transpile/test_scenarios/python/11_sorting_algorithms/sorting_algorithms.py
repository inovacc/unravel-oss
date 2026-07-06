"""Sorting algorithm implementations with benchmarking.

Covers: generics (TypeVar), Comparable protocol, closures,
        time measurement, nested functions, recursion,
        slice assignment, *args/**kwargs, walrus operator.
"""

from __future__ import annotations

import random
import time
from dataclasses import dataclass, field
from typing import Callable, Generic, Protocol, TypeVar


class Comparable(Protocol):
    """Protocol for comparable types."""

    def __lt__(self, other) -> bool: ...
    def __le__(self, other) -> bool: ...
    def __gt__(self, other) -> bool: ...
    def __ge__(self, other) -> bool: ...


T = TypeVar("T")
CT = TypeVar("CT", bound=Comparable)


@dataclass
class SortResult:
    """Result of a sorting operation."""

    algorithm: str
    comparisons: int
    swaps: int
    duration_ms: float
    sorted_data: list

    @property
    def ops_total(self) -> int:
        return self.comparisons + self.swaps


def bubble_sort(arr: list[CT]) -> SortResult:
    """Bubble sort with optimization for already-sorted detection."""
    data = arr.copy()
    n = len(data)
    comparisons = 0
    swaps = 0
    start = time.monotonic()

    for i in range(n):
        swapped = False
        for j in range(0, n - i - 1):
            comparisons += 1
            if data[j] > data[j + 1]:
                data[j], data[j + 1] = data[j + 1], data[j]
                swaps += 1
                swapped = True
        if not swapped:
            break

    duration = (time.monotonic() - start) * 1000
    return SortResult("bubble_sort", comparisons, swaps, duration, data)


def insertion_sort(arr: list[CT]) -> SortResult:
    """Insertion sort — efficient for small or nearly sorted arrays."""
    data = arr.copy()
    comparisons = 0
    swaps = 0
    start = time.monotonic()

    for i in range(1, len(data)):
        key = data[i]
        j = i - 1
        while j >= 0:
            comparisons += 1
            if data[j] > key:
                data[j + 1] = data[j]
                swaps += 1
                j -= 1
            else:
                break
        data[j + 1] = key

    duration = (time.monotonic() - start) * 1000
    return SortResult("insertion_sort", comparisons, swaps, duration, data)


def selection_sort(arr: list[CT]) -> SortResult:
    """Selection sort — finds minimum and places it."""
    data = arr.copy()
    n = len(data)
    comparisons = 0
    swaps = 0
    start = time.monotonic()

    for i in range(n):
        min_idx = i
        for j in range(i + 1, n):
            comparisons += 1
            if data[j] < data[min_idx]:
                min_idx = j
        if min_idx != i:
            data[i], data[min_idx] = data[min_idx], data[i]
            swaps += 1

    duration = (time.monotonic() - start) * 1000
    return SortResult("selection_sort", comparisons, swaps, duration, data)


def merge_sort(arr: list[CT]) -> SortResult:
    """Merge sort — divide and conquer, stable sort."""
    data = arr.copy()
    stats = {"comparisons": 0, "swaps": 0}
    start = time.monotonic()

    def _merge(left: list[CT], right: list[CT]) -> list[CT]:
        result: list[CT] = []
        i = j = 0
        while i < len(left) and j < len(right):
            stats["comparisons"] += 1
            if left[i] <= right[j]:
                result.append(left[i])
                i += 1
            else:
                result.append(right[j])
                j += 1
            stats["swaps"] += 1
        result.extend(left[i:])
        result.extend(right[j:])
        return result

    def _sort(data: list[CT]) -> list[CT]:
        if len(data) <= 1:
            return data
        mid = len(data) // 2
        left = _sort(data[:mid])
        right = _sort(data[mid:])
        return _merge(left, right)

    sorted_data = _sort(data)
    duration = (time.monotonic() - start) * 1000
    return SortResult("merge_sort", stats["comparisons"], stats["swaps"], duration, sorted_data)


def quick_sort(arr: list[CT]) -> SortResult:
    """Quick sort with median-of-three pivot selection."""
    data = arr.copy()
    stats = {"comparisons": 0, "swaps": 0}
    start = time.monotonic()

    def _partition(low: int, high: int) -> int:
        # Median-of-three pivot
        mid = (low + high) // 2
        if data[low] > data[mid]:
            data[low], data[mid] = data[mid], data[low]
            stats["swaps"] += 1
        if data[low] > data[high]:
            data[low], data[high] = data[high], data[low]
            stats["swaps"] += 1
        if data[mid] > data[high]:
            data[mid], data[high] = data[high], data[mid]
            stats["swaps"] += 1
        stats["comparisons"] += 3

        data[mid], data[high - 1] = data[high - 1], data[mid]
        stats["swaps"] += 1
        pivot = data[high - 1]

        i = low
        j = high - 1
        while True:
            i += 1
            while data[i] < pivot:
                stats["comparisons"] += 1
                i += 1
            stats["comparisons"] += 1
            j -= 1
            while data[j] > pivot:
                stats["comparisons"] += 1
                j -= 1
            stats["comparisons"] += 1
            if i >= j:
                break
            data[i], data[j] = data[j], data[i]
            stats["swaps"] += 1

        data[i], data[high - 1] = data[high - 1], data[i]
        stats["swaps"] += 1
        return i

    def _sort(low: int, high: int) -> None:
        if high - low < 2:
            if high > low:
                stats["comparisons"] += 1
                if data[low] > data[high]:
                    data[low], data[high] = data[high], data[low]
                    stats["swaps"] += 1
            return
        pivot_idx = _partition(low, high)
        _sort(low, pivot_idx - 1)
        _sort(pivot_idx + 1, high)

    if len(data) > 1:
        _sort(0, len(data) - 1)

    duration = (time.monotonic() - start) * 1000
    return SortResult("quick_sort", stats["comparisons"], stats["swaps"], duration, data)


def heap_sort(arr: list[CT]) -> SortResult:
    """Heap sort using max-heap."""
    data = arr.copy()
    n = len(data)
    comparisons = 0
    swaps = 0
    start = time.monotonic()

    def _sift_down(start_idx: int, end_idx: int) -> None:
        nonlocal comparisons, swaps
        root = start_idx
        while (child := 2 * root + 1) <= end_idx:
            if child + 1 <= end_idx:
                comparisons += 1
                if data[child] < data[child + 1]:
                    child += 1
            comparisons += 1
            if data[root] < data[child]:
                data[root], data[child] = data[child], data[root]
                swaps += 1
                root = child
            else:
                break

    # Build max heap
    for i in range(n // 2 - 1, -1, -1):
        _sift_down(i, n - 1)

    # Extract elements
    for end in range(n - 1, 0, -1):
        data[0], data[end] = data[end], data[0]
        swaps += 1
        _sift_down(0, end - 1)

    duration = (time.monotonic() - start) * 1000
    return SortResult("heap_sort", comparisons, swaps, duration, data)


SortFunction = Callable[[list], SortResult]


@dataclass
class BenchmarkSuite:
    """Benchmark multiple sorting algorithms."""

    algorithms: dict[str, SortFunction] = field(default_factory=dict)

    def register(self, name: str, func: SortFunction) -> None:
        self.algorithms[name] = func

    def run(self, data: list, iterations: int = 3) -> list[SortResult]:
        """Run all algorithms and collect results."""
        results: list[SortResult] = []
        for name, func in sorted(self.algorithms.items()):
            best: SortResult | None = None
            for _ in range(iterations):
                result = func(data)
                if best is None or result.duration_ms < best.duration_ms:
                    best = result
            if best is not None:
                results.append(best)
        return results

    @staticmethod
    def generate_test_data(size: int, kind: str = "random") -> list[int]:
        """Generate test data of various patterns."""
        if kind == "random":
            return [random.randint(0, size * 10) for _ in range(size)]
        elif kind == "sorted":
            return list(range(size))
        elif kind == "reversed":
            return list(range(size, 0, -1))
        elif kind == "nearly_sorted":
            data = list(range(size))
            swaps = max(1, size // 20)
            for _ in range(swaps):
                i, j = random.randint(0, size - 1), random.randint(0, size - 1)
                data[i], data[j] = data[j], data[i]
            return data
        elif kind == "duplicates":
            return [random.randint(0, size // 10) for _ in range(size)]
        else:
            raise ValueError(f"Unknown data kind: {kind}")

    def format_results(self, results: list[SortResult]) -> str:
        """Format benchmark results as a table."""
        lines = [f"{'Algorithm':<20} {'Comparisons':>12} {'Swaps':>8} {'Time (ms)':>10}"]
        lines.append("-" * 54)
        for r in sorted(results, key=lambda x: x.duration_ms):
            lines.append(
                f"{r.algorithm:<20} {r.comparisons:>12} {r.swaps:>8} {r.duration_ms:>10.3f}"
            )
        return "\n".join(lines)
