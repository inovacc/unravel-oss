"""Task scheduler with dependency resolution and execution.

Covers: topological sort, graph algorithms, threading.Event,
        concurrent.futures, logging, __slots__ with properties,
        weakref, singledispatch, type aliases, TypeGuard.
"""

from __future__ import annotations

import logging
import threading
import time
from concurrent.futures import ThreadPoolExecutor, Future, as_completed
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum, auto
from functools import singledispatch
from typing import Any, Callable


logger = logging.getLogger(__name__)


class TaskStatus(Enum):
    """Task execution status."""

    PENDING = auto()
    QUEUED = auto()
    RUNNING = auto()
    COMPLETED = auto()
    FAILED = auto()
    SKIPPED = auto()
    CANCELLED = auto()


class TaskPriority(Enum):
    """Task priority levels."""

    LOW = 1
    NORMAL = 5
    HIGH = 8
    CRITICAL = 10

    def __lt__(self, other: TaskPriority) -> bool:
        return self.value < other.value


TaskAction = Callable[[], Any]


@dataclass
class TaskResult:
    """Result of a task execution."""

    task_id: str
    status: TaskStatus
    output: Any = None
    error: str = ""
    started_at: datetime | None = None
    finished_at: datetime | None = None

    @property
    def duration_ms(self) -> int:
        if self.started_at and self.finished_at:
            delta = self.finished_at - self.started_at
            return int(delta.total_seconds() * 1000)
        return 0

    @property
    def success(self) -> bool:
        return self.status == TaskStatus.COMPLETED


class Task:
    """A schedulable task with dependencies."""

    __slots__ = (
        "_id", "_name", "_action", "_status", "_priority",
        "_dependencies", "_result", "_retries", "_max_retries",
        "_timeout", "_tags",
    )

    def __init__(
        self,
        task_id: str,
        name: str,
        action: TaskAction,
        priority: TaskPriority = TaskPriority.NORMAL,
        max_retries: int = 0,
        timeout: float | None = None,
        tags: list[str] | None = None,
    ) -> None:
        self._id = task_id
        self._name = name
        self._action = action
        self._status = TaskStatus.PENDING
        self._priority = priority
        self._dependencies: set[str] = set()
        self._result: TaskResult | None = None
        self._retries = 0
        self._max_retries = max_retries
        self._timeout = timeout
        self._tags = set(tags) if tags else set()

    @property
    def id(self) -> str:
        return self._id

    @property
    def name(self) -> str:
        return self._name

    @property
    def status(self) -> TaskStatus:
        return self._status

    @status.setter
    def status(self, value: TaskStatus) -> None:
        self._status = value

    @property
    def priority(self) -> TaskPriority:
        return self._priority

    @property
    def dependencies(self) -> set[str]:
        return self._dependencies.copy()

    @property
    def result(self) -> TaskResult | None:
        return self._result

    @property
    def tags(self) -> set[str]:
        return self._tags.copy()

    def depends_on(self, *task_ids: str) -> Task:
        """Add dependencies. Returns self for chaining."""
        self._dependencies.update(task_ids)
        return self

    def execute(self) -> TaskResult:
        """Execute the task action."""
        self._status = TaskStatus.RUNNING
        started = datetime.now(timezone.utc)
        try:
            output = self._action()
            self._status = TaskStatus.COMPLETED
            self._result = TaskResult(
                task_id=self._id,
                status=TaskStatus.COMPLETED,
                output=output,
                started_at=started,
                finished_at=datetime.now(timezone.utc),
            )
        except Exception as e:
            self._retries += 1
            if self._retries <= self._max_retries:
                self._status = TaskStatus.PENDING
            else:
                self._status = TaskStatus.FAILED
            self._result = TaskResult(
                task_id=self._id,
                status=TaskStatus.FAILED,
                error=str(e),
                started_at=started,
                finished_at=datetime.now(timezone.utc),
            )
        return self._result

    def __repr__(self) -> str:
        return f"Task({self._id!r}, status={self._status.name})"


class CyclicDependencyError(Exception):
    """Raised when task dependencies form a cycle."""

    def __init__(self, cycle: list[str]) -> None:
        self.cycle = cycle
        super().__init__(f"Cyclic dependency detected: {' -> '.join(cycle)}")


class TaskGraph:
    """Directed acyclic graph of task dependencies."""

    def __init__(self) -> None:
        self._tasks: dict[str, Task] = {}

    def add(self, task: Task) -> None:
        self._tasks[task.id] = task

    def get(self, task_id: str) -> Task | None:
        return self._tasks.get(task_id)

    def __len__(self) -> int:
        return len(self._tasks)

    def __contains__(self, task_id: str) -> bool:
        return task_id in self._tasks

    def topological_sort(self) -> list[Task]:
        """Return tasks in dependency order (Kahn's algorithm)."""
        in_degree: dict[str, int] = {tid: 0 for tid in self._tasks}
        for task in self._tasks.values():
            for dep_id in task.dependencies:
                if dep_id in in_degree:
                    in_degree[task.id] = in_degree.get(task.id, 0)

        # Calculate actual in-degrees
        adj: dict[str, list[str]] = {tid: [] for tid in self._tasks}
        for task in self._tasks.values():
            for dep_id in task.dependencies:
                if dep_id in adj:
                    adj[dep_id].append(task.id)
                    in_degree[task.id] += 1

        # Kahn's algorithm
        queue: list[str] = [tid for tid, deg in in_degree.items() if deg == 0]
        queue.sort(key=lambda tid: self._tasks[tid].priority.value, reverse=True)
        result: list[Task] = []

        while queue:
            current = queue.pop(0)
            result.append(self._tasks[current])
            for neighbor in adj[current]:
                in_degree[neighbor] -= 1
                if in_degree[neighbor] == 0:
                    queue.append(neighbor)
            queue.sort(key=lambda tid: self._tasks[tid].priority.value, reverse=True)

        if len(result) != len(self._tasks):
            # Find cycle
            remaining = set(self._tasks.keys()) - {t.id for t in result}
            raise CyclicDependencyError(sorted(remaining))

        return result

    def ready_tasks(self, completed: set[str]) -> list[Task]:
        """Return tasks whose dependencies are all completed."""
        ready = []
        for task in self._tasks.values():
            if task.status != TaskStatus.PENDING:
                continue
            if task.dependencies.issubset(completed):
                ready.append(task)
        ready.sort(key=lambda t: t.priority.value, reverse=True)
        return ready


@singledispatch
def format_result(result: Any) -> str:
    """Format a task result for display."""
    return str(result)


@format_result.register(TaskResult)
def _format_task_result(result: TaskResult) -> str:
    status = "OK" if result.success else "FAIL"
    return f"[{status}] {result.task_id} ({result.duration_ms}ms)"


@format_result.register(list)
def _format_result_list(results: list) -> str:
    return "\n".join(format_result(r) for r in results)


class TaskScheduler:
    """Execute tasks respecting dependencies with parallelism."""

    def __init__(self, max_workers: int = 4) -> None:
        self._graph = TaskGraph()
        self._max_workers = max_workers
        self._results: dict[str, TaskResult] = {}
        self._lock = threading.Lock()
        self._cancel_event = threading.Event()

    def add(self, task: Task) -> None:
        """Add a task to the scheduler."""
        self._graph.add(task)

    @property
    def task_count(self) -> int:
        return len(self._graph)

    def run(self) -> list[TaskResult]:
        """Execute all tasks in dependency order with parallelism."""
        # Validate no cycles
        self._graph.topological_sort()

        completed: set[str] = set()
        results: list[TaskResult] = []

        with ThreadPoolExecutor(max_workers=self._max_workers) as executor:
            futures: dict[Future, Task] = {}

            while len(completed) < len(self._graph) and not self._cancel_event.is_set():
                # Find ready tasks
                ready = self._graph.ready_tasks(completed)
                ready = [t for t in ready if t.id not in {ft.id for ft in futures.values()}]

                for task in ready:
                    task.status = TaskStatus.QUEUED
                    future = executor.submit(task.execute)
                    futures[future] = task

                if not futures:
                    break

                # Wait for at least one to complete
                done_futures = []
                for future in as_completed(futures):
                    done_futures.append(future)
                    break  # Process one at a time to check for new ready tasks

                for future in done_futures:
                    task = futures.pop(future)
                    result = future.result()
                    if result is not None:
                        results.append(result)
                        with self._lock:
                            self._results[task.id] = result
                        if result.success:
                            completed.add(task.id)
                        else:
                            logger.error("Task %s failed: %s", task.id, result.error)
                            # Skip dependent tasks
                            self._skip_dependents(task.id, results, completed)

        return results

    def _skip_dependents(
        self, failed_id: str, results: list[TaskResult], completed: set[str]
    ) -> None:
        """Skip tasks that depend on a failed task."""
        for task_id in list(self._graph._tasks.keys()):
            task = self._graph.get(task_id)
            if task and failed_id in task.dependencies and task.status == TaskStatus.PENDING:
                task.status = TaskStatus.SKIPPED
                result = TaskResult(
                    task_id=task.id,
                    status=TaskStatus.SKIPPED,
                    error=f"Skipped: dependency {failed_id} failed",
                )
                results.append(result)
                completed.add(task.id)

    def cancel(self) -> None:
        """Cancel remaining tasks."""
        self._cancel_event.set()

    def get_result(self, task_id: str) -> TaskResult | None:
        with self._lock:
            return self._results.get(task_id)

    def summary(self) -> dict[str, int]:
        """Get execution summary."""
        counts: dict[str, int] = {}
        for result in self._results.values():
            key = result.status.name
            counts[key] = counts.get(key, 0) + 1
        return counts
