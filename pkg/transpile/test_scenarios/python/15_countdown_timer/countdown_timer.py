"""Countdown timer and scheduling system.

Covers: datetime arithmetic, timedelta, heapq (priority queue),
        threading.Timer, __enter__/__exit__ (context manager class),
        __call__, operator module, bisect, typing overloads.
"""

from __future__ import annotations

import bisect
import heapq
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum, auto
from typing import Any, Callable


class TimerState(Enum):
    """Timer states."""

    IDLE = auto()
    RUNNING = auto()
    PAUSED = auto()
    FINISHED = auto()
    CANCELLED = auto()


@dataclass
class Duration:
    """Human-friendly duration representation."""

    hours: int = 0
    minutes: int = 0
    seconds: int = 0

    def __post_init__(self) -> None:
        # Normalize
        total = self.total_seconds
        if total < 0:
            raise ValueError("Duration cannot be negative")
        self.hours = total // 3600
        self.minutes = (total % 3600) // 60
        self.seconds = total % 60

    @property
    def total_seconds(self) -> int:
        return self.hours * 3600 + self.minutes * 60 + self.seconds

    def to_timedelta(self) -> timedelta:
        return timedelta(seconds=self.total_seconds)

    @classmethod
    def from_seconds(cls, seconds: int) -> Duration:
        return cls(seconds=seconds)

    @classmethod
    def from_timedelta(cls, td: timedelta) -> Duration:
        return cls(seconds=int(td.total_seconds()))

    def __str__(self) -> str:
        return f"{self.hours:02d}:{self.minutes:02d}:{self.seconds:02d}"

    def __repr__(self) -> str:
        return f"Duration({self.hours}h {self.minutes}m {self.seconds}s)"

    def __add__(self, other: Duration) -> Duration:
        return Duration.from_seconds(self.total_seconds + other.total_seconds)

    def __sub__(self, other: Duration) -> Duration:
        return Duration.from_seconds(max(0, self.total_seconds - other.total_seconds))

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Duration):
            return NotImplemented
        return self.total_seconds == other.total_seconds

    def __lt__(self, other: Duration) -> bool:
        return self.total_seconds < other.total_seconds

    def __le__(self, other: Duration) -> bool:
        return self.total_seconds <= other.total_seconds

    def __bool__(self) -> bool:
        return self.total_seconds > 0


class CountdownTimer:
    """A countdown timer with pause/resume support."""

    def __init__(self, duration: Duration, label: str = "") -> None:
        self._duration = duration
        self._remaining = duration.total_seconds
        self._state = TimerState.IDLE
        self._label = label
        self._started_at: float | None = None
        self._paused_at: float | None = None
        self._callbacks: list[Callable[[], None]] = []

    @property
    def state(self) -> TimerState:
        return self._state

    @property
    def label(self) -> str:
        return self._label

    @property
    def remaining(self) -> Duration:
        if self._state == TimerState.RUNNING and self._started_at is not None:
            elapsed = time.monotonic() - self._started_at
            secs = max(0, int(self._remaining - elapsed))
            return Duration.from_seconds(secs)
        return Duration.from_seconds(max(0, int(self._remaining)))

    @property
    def progress(self) -> float:
        """Progress as percentage (0.0 to 100.0)."""
        total = self._duration.total_seconds
        if total == 0:
            return 100.0
        remaining = self.remaining.total_seconds
        return ((total - remaining) / total) * 100

    def on_finish(self, callback: Callable[[], None]) -> None:
        """Register a callback for when timer finishes."""
        self._callbacks.append(callback)

    def start(self) -> None:
        """Start or resume the timer."""
        if self._state in (TimerState.FINISHED, TimerState.CANCELLED):
            raise RuntimeError(f"Cannot start timer in {self._state.name} state")
        self._started_at = time.monotonic()
        self._state = TimerState.RUNNING

    def pause(self) -> None:
        """Pause the timer."""
        if self._state != TimerState.RUNNING:
            return
        if self._started_at is not None:
            elapsed = time.monotonic() - self._started_at
            self._remaining = max(0, self._remaining - elapsed)
        self._state = TimerState.PAUSED
        self._paused_at = time.monotonic()

    def resume(self) -> None:
        """Resume a paused timer."""
        if self._state != TimerState.PAUSED:
            return
        self.start()

    def cancel(self) -> None:
        """Cancel the timer."""
        self._state = TimerState.CANCELLED

    def reset(self) -> None:
        """Reset timer to original duration."""
        self._remaining = self._duration.total_seconds
        self._state = TimerState.IDLE
        self._started_at = None
        self._paused_at = None

    def check(self) -> bool:
        """Check if timer has finished. Fires callbacks if so."""
        if self._state != TimerState.RUNNING:
            return self._state == TimerState.FINISHED
        if self.remaining.total_seconds <= 0:
            self._state = TimerState.FINISHED
            for callback in self._callbacks:
                callback()
            return True
        return False


@dataclass(order=True)
class ScheduledEvent:
    """An event scheduled at a specific time."""

    run_at: datetime
    label: str = field(compare=False)
    callback: Callable[[], None] = field(compare=False, repr=False)
    recurring: timedelta | None = field(default=None, compare=False)
    _cancelled: bool = field(default=False, compare=False, repr=False)

    @property
    def cancelled(self) -> bool:
        return self._cancelled

    def cancel(self) -> None:
        self._cancelled = True


class Scheduler:
    """Event scheduler using a priority queue."""

    def __init__(self) -> None:
        self._events: list[ScheduledEvent] = []
        self._lock = threading.Lock()

    def schedule(
        self,
        label: str,
        run_at: datetime,
        callback: Callable[[], None],
        recurring: timedelta | None = None,
    ) -> ScheduledEvent:
        """Schedule an event."""
        event = ScheduledEvent(
            run_at=run_at,
            label=label,
            callback=callback,
            recurring=recurring,
        )
        with self._lock:
            heapq.heappush(self._events, event)
        return event

    def schedule_after(
        self,
        label: str,
        delay: Duration,
        callback: Callable[[], None],
    ) -> ScheduledEvent:
        """Schedule an event after a delay."""
        run_at = datetime.now(timezone.utc) + delay.to_timedelta()
        return self.schedule(label, run_at, callback)

    def pending_count(self) -> int:
        """Count non-cancelled pending events."""
        with self._lock:
            return sum(1 for e in self._events if not e.cancelled)

    def next_event(self) -> ScheduledEvent | None:
        """Peek at the next event without removing it."""
        with self._lock:
            while self._events:
                if self._events[0].cancelled:
                    heapq.heappop(self._events)
                    continue
                return self._events[0]
            return None

    def tick(self) -> list[ScheduledEvent]:
        """Process all events due now. Returns list of fired events."""
        now = datetime.now(timezone.utc)
        fired: list[ScheduledEvent] = []

        with self._lock:
            while self._events and self._events[0].run_at <= now:
                event = heapq.heappop(self._events)
                if event.cancelled:
                    continue
                event.callback()
                fired.append(event)
                # Re-schedule recurring events
                if event.recurring:
                    next_event = ScheduledEvent(
                        run_at=event.run_at + event.recurring,
                        label=event.label,
                        callback=event.callback,
                        recurring=event.recurring,
                    )
                    heapq.heappush(self._events, next_event)

        return fired

    def cancel_all(self) -> int:
        """Cancel all pending events. Returns count cancelled."""
        with self._lock:
            count = 0
            for event in self._events:
                if not event.cancelled:
                    event.cancel()
                    count += 1
            self._events.clear()
            return count


class StopwatchLap:
    """A single stopwatch lap."""

    def __init__(self, number: int, elapsed: float, split: float) -> None:
        self.number = number
        self.elapsed = elapsed
        self.split = split

    def __str__(self) -> str:
        return f"Lap {self.number}: {self.split:.3f}s (total: {self.elapsed:.3f}s)"


class Stopwatch:
    """Stopwatch with lap tracking. Supports context manager protocol."""

    def __init__(self, label: str = "") -> None:
        self.label = label
        self._start_time: float | None = None
        self._stop_time: float | None = None
        self._laps: list[StopwatchLap] = []
        self._last_lap_time: float = 0.0

    def __enter__(self) -> Stopwatch:
        self.start()
        return self

    def __exit__(self, *args: Any) -> None:
        self.stop()

    def start(self) -> None:
        self._start_time = time.monotonic()
        self._last_lap_time = 0.0

    def stop(self) -> float:
        if self._start_time is None:
            return 0.0
        self._stop_time = time.monotonic()
        return self._stop_time - self._start_time

    def lap(self) -> StopwatchLap:
        """Record a lap."""
        if self._start_time is None:
            raise RuntimeError("Stopwatch not started")
        elapsed = time.monotonic() - self._start_time
        split = elapsed - self._last_lap_time
        self._last_lap_time = elapsed
        lap = StopwatchLap(len(self._laps) + 1, elapsed, split)
        self._laps.append(lap)
        return lap

    @property
    def elapsed(self) -> float:
        if self._start_time is None:
            return 0.0
        end = self._stop_time or time.monotonic()
        return end - self._start_time

    @property
    def laps(self) -> list[StopwatchLap]:
        return self._laps.copy()

    @property
    def fastest_lap(self) -> StopwatchLap | None:
        if not self._laps:
            return None
        return min(self._laps, key=lambda lap: lap.split)

    @property
    def slowest_lap(self) -> StopwatchLap | None:
        if not self._laps:
            return None
        return max(self._laps, key=lambda lap: lap.split)
