"""A data processing pipeline with generators, decorators, protocols, and context managers.

Demonstrates: generators/yield, decorators, Protocol, context managers, comprehensions,
              functools, typing, generic patterns.
Difficulty: Medium-Hard (~300 LOC)
"""

from __future__ import annotations

import csv
import io
import functools
import logging
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Any, Callable, Generator, Generic, Iterator, Protocol, TypeVar

logger = logging.getLogger(__name__)

T = TypeVar("T")
R = TypeVar("R")


# --- Protocols ---

class Transformer(Protocol[T, R]):
    """Protocol for data transformers."""

    def transform(self, data: T) -> R:
        ...


class DataSource(Protocol[T]):
    """Protocol for data sources that yield records."""

    def records(self) -> Iterator[T]:
        ...


class DataSink(Protocol[T]):
    """Protocol for data sinks that consume records."""

    def write(self, record: T) -> None:
        ...

    def flush(self) -> None:
        ...


# --- Decorators ---

def retry(max_attempts: int = 3, delay: float = 0.1) -> Callable:
    """Decorator that retries a function on failure."""

    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            last_error: Exception | None = None
            for attempt in range(1, max_attempts + 1):
                try:
                    return func(*args, **kwargs)
                except Exception as e:
                    last_error = e
                    logger.warning(
                        "Attempt %d/%d failed for %s: %s",
                        attempt, max_attempts, func.__name__, e,
                    )
                    if attempt < max_attempts:
                        time.sleep(delay * attempt)
            raise RuntimeError(
                f"All {max_attempts} attempts failed for {func.__name__}"
            ) from last_error
        return wrapper
    return decorator


def timed(func: Callable) -> Callable:
    """Decorator that logs execution time."""

    @functools.wraps(func)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        start = time.monotonic()
        try:
            return func(*args, **kwargs)
        finally:
            elapsed = time.monotonic() - start
            logger.info("%s took %.3fs", func.__name__, elapsed)
    return wrapper


def validate_schema(required_fields: list[str]) -> Callable:
    """Decorator that validates dict records have required fields."""

    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(self: Any, record: dict[str, Any]) -> Any:
            missing = [f for f in required_fields if f not in record]
            if missing:
                raise ValueError(f"Missing required fields: {missing}")
            return func(self, record)
        return wrapper
    return decorator


# --- Context managers ---

@contextmanager
def batch_processor(name: str, batch_size: int = 100) -> Generator[list[Any], None, None]:
    """Context manager that accumulates records and flushes in batches."""
    batch: list[Any] = []
    logger.info("Starting batch processor: %s (batch_size=%d)", name, batch_size)
    try:
        yield batch
    finally:
        if batch:
            logger.info("Flushing final batch of %d records for %s", len(batch), name)
        logger.info("Batch processor %s finished", name)


@contextmanager
def pipeline_context(name: str) -> Generator[dict[str, Any], None, None]:
    """Context manager that tracks pipeline execution metrics."""
    ctx: dict[str, Any] = {
        "name": name,
        "start_time": time.monotonic(),
        "records_processed": 0,
        "errors": 0,
    }
    logger.info("Pipeline '%s' started", name)
    try:
        yield ctx
    except Exception as e:
        ctx["errors"] += 1
        logger.error("Pipeline '%s' failed: %s", name, e)
        raise
    finally:
        ctx["elapsed"] = time.monotonic() - ctx["start_time"]
        logger.info(
            "Pipeline '%s' finished: %d records, %d errors, %.3fs",
            name, ctx["records_processed"], ctx["errors"], ctx["elapsed"],
        )


# --- Data types ---

@dataclass
class Record:
    """A generic data record."""
    fields: dict[str, Any]
    metadata: dict[str, str] = field(default_factory=dict)

    def get(self, key: str, default: Any = None) -> Any:
        return self.fields.get(key, default)

    def __getitem__(self, key: str) -> Any:
        return self.fields[key]


@dataclass
class PipelineStats:
    """Statistics collected during pipeline execution."""
    input_count: int = 0
    output_count: int = 0
    filtered_count: int = 0
    error_count: int = 0
    duration_seconds: float = 0.0


# --- Generators ---

def csv_reader(data: str) -> Generator[dict[str, str], None, None]:
    """Generator that yields dicts from CSV data."""
    reader = csv.DictReader(io.StringIO(data))
    for row in reader:
        yield dict(row)


def chunked(iterable: Iterator[T], size: int) -> Generator[list[T], None, None]:
    """Generator that yields fixed-size chunks from an iterator."""
    chunk: list[T] = []
    for item in iterable:
        chunk.append(item)
        if len(chunk) >= size:
            yield chunk
            chunk = []
    if chunk:
        yield chunk


def filtered_records(
    source: Iterator[dict[str, Any]],
    predicate: Callable[[dict[str, Any]], bool],
) -> Generator[dict[str, Any], None, None]:
    """Generator that filters records based on a predicate."""
    for record in source:
        if predicate(record):
            yield record


# --- Transformers ---

class FieldMapper:
    """Renames fields in a record."""

    def __init__(self, mapping: dict[str, str]) -> None:
        self._mapping = mapping

    def transform(self, data: dict[str, Any]) -> dict[str, Any]:
        return {
            self._mapping.get(k, k): v
            for k, v in data.items()
        }


class TypeCaster:
    """Casts field values to specified types."""

    def __init__(self, type_map: dict[str, type]) -> None:
        self._type_map = type_map

    @validate_schema(required_fields=[])
    def transform(self, record: dict[str, Any]) -> dict[str, Any]:
        result = dict(record)
        for field_name, target_type in self._type_map.items():
            if field_name in result:
                try:
                    result[field_name] = target_type(result[field_name])
                except (ValueError, TypeError) as e:
                    logger.warning("Failed to cast %s to %s: %s", field_name, target_type.__name__, e)
        return result


class Aggregator:
    """Aggregates numeric field values."""

    def __init__(self, group_by: str, agg_field: str) -> None:
        self._group_by = group_by
        self._agg_field = agg_field
        self._groups: dict[str, list[float]] = {}

    def add(self, record: dict[str, Any]) -> None:
        key = str(record.get(self._group_by, "unknown"))
        value = float(record.get(self._agg_field, 0))
        if key not in self._groups:
            self._groups[key] = []
        self._groups[key].append(value)

    def results(self) -> dict[str, dict[str, float]]:
        return {
            key: {
                "count": float(len(values)),
                "sum": sum(values),
                "avg": sum(values) / len(values) if values else 0.0,
                "min": min(values) if values else 0.0,
                "max": max(values) if values else 0.0,
            }
            for key, values in sorted(self._groups.items())
        }


# --- Pipeline ---

class Pipeline:
    """Configurable data processing pipeline."""

    def __init__(self, name: str) -> None:
        self._name = name
        self._transformers: list[Callable[[dict[str, Any]], dict[str, Any]]] = []
        self._filters: list[Callable[[dict[str, Any]], bool]] = []

    def add_transformer(self, transformer: Callable[[dict[str, Any]], dict[str, Any]]) -> Pipeline:
        self._transformers.append(transformer)
        return self

    def add_filter(self, predicate: Callable[[dict[str, Any]], bool]) -> Pipeline:
        self._filters.append(predicate)
        return self

    @timed
    def execute(self, source: Iterator[dict[str, Any]]) -> PipelineStats:
        """Execute the pipeline on a data source."""
        stats = PipelineStats()

        with pipeline_context(self._name) as ctx:
            for record in source:
                stats.input_count += 1

                # Apply filters
                if not all(f(record) for f in self._filters):
                    stats.filtered_count += 1
                    continue

                # Apply transformers
                try:
                    current = record
                    for transformer in self._transformers:
                        current = transformer(current)
                    stats.output_count += 1
                    ctx["records_processed"] += 1
                except Exception as e:
                    stats.error_count += 1
                    ctx["errors"] += 1
                    logger.error("Transform error: %s", e)

        return stats


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

    # Sample CSV data
    csv_data = """name,age,city,salary
Alice,30,New York,85000
Bob,25,San Francisco,92000
Charlie,35,New York,78000
Diana,28,Chicago,65000
Eve,32,San Francisco,110000
Frank,45,New York,95000
Grace,27,Chicago,72000
"""

    # Build pipeline
    pipeline = Pipeline("employee_analysis")

    # Rename fields
    mapper = FieldMapper({"name": "employee_name", "city": "location"})
    pipeline.add_transformer(mapper.transform)

    # Cast types
    caster = TypeCaster({"age": int, "salary": float})
    pipeline.add_transformer(caster.transform)

    # Filter: age >= 28
    pipeline.add_filter(lambda r: int(r.get("age", 0)) >= 28)

    # Execute
    source = csv_reader(csv_data)
    stats = pipeline.execute(source)

    print(f"\nPipeline Stats:")
    print(f"  Input:    {stats.input_count}")
    print(f"  Output:   {stats.output_count}")
    print(f"  Filtered: {stats.filtered_count}")
    print(f"  Errors:   {stats.error_count}")

    # Aggregation example
    aggregator = Aggregator(group_by="city", agg_field="salary")
    for record in csv_reader(csv_data):
        aggregator.add(record)

    print("\nSalary by city:")
    for city, agg in aggregator.results().items():
        print(f"  {city}: avg={agg['avg']:.0f}, count={agg['count']:.0f}")

    # Chunked processing example
    print("\nChunked processing:")
    records = list(csv_reader(csv_data))
    for i, chunk in enumerate(chunked(iter(records), 3)):
        names = [r["name"] for r in chunk]
        print(f"  Chunk {i}: {names}")


if __name__ == "__main__":
    main()
