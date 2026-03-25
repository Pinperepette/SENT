from __future__ import annotations

"""
Priority queue with backpressure and metrics.

Features:
  - Priority ordering: higher score → processed first
  - Backpressure: when queue exceeds max_size, lowest-priority tasks are dropped
  - Dedup: same package/version is never enqueued twice
  - Metrics: tracks enqueued, dropped, processed counts
"""

import heapq
import threading
import time
from dataclasses import dataclass, field


@dataclass(order=True)
class AnalysisTask:
    # heapq is a min-heap, so negate score for highest-first ordering
    _neg_score: float = field(compare=True, repr=False)
    enqueued_at: float = field(compare=True, repr=False)
    package_name: str = field(compare=False)
    ecosystem: str = field(compare=False)
    new_version: str = field(compare=False)
    old_version: str = field(compare=False)
    priority_score: float = field(compare=False, default=0.0)

    @staticmethod
    def create(package_name: str, ecosystem: str, new_version: str,
               old_version: str, priority_score: float) -> AnalysisTask:
        return AnalysisTask(
            _neg_score=-priority_score,
            enqueued_at=time.monotonic(),
            package_name=package_name,
            ecosystem=ecosystem,
            new_version=new_version,
            old_version=old_version,
            priority_score=priority_score,
        )

    @property
    def key(self) -> str:
        return f"{self.ecosystem}/{self.package_name}@{self.new_version}"


@dataclass
class QueueMetrics:
    enqueued: int = 0
    dropped: int = 0
    processed: int = 0
    total_wait_ms: float = 0.0   # cumulative time tasks spent in queue
    peak_size: int = 0

    @property
    def avg_wait_ms(self) -> float:
        return self.total_wait_ms / self.processed if self.processed else 0.0


class AnalysisQueue:
    def __init__(self, max_size: int = 200):
        self._heap: list[AnalysisTask] = []
        self._lock = threading.Lock()
        self._not_empty = threading.Condition(self._lock)
        self._seen: set[str] = set()
        self._max_size = max_size
        self._shutdown = False
        self.metrics = QueueMetrics()

    def enqueue(self, task: AnalysisTask) -> bool:
        """Add task. Returns False if duplicate. Drops lowest-priority if full."""
        with self._not_empty:
            if task.key in self._seen:
                return False

            # Backpressure: if full, drop the lowest-priority item
            if len(self._heap) >= self._max_size:
                # Peek at the lowest priority (highest _neg_score = lowest priority)
                # The heap invariant means we need to find the max _neg_score
                worst = max(self._heap)
                if task._neg_score < worst._neg_score:
                    # New task is higher priority — drop the worst
                    self._heap.remove(worst)
                    heapq.heapify(self._heap)
                    self._seen.discard(worst.key)
                    self.metrics.dropped += 1
                else:
                    # New task is lower priority — drop it
                    self.metrics.dropped += 1
                    return False

            self._seen.add(task.key)
            heapq.heappush(self._heap, task)
            self.metrics.enqueued += 1
            self.metrics.peak_size = max(self.metrics.peak_size, len(self._heap))
            self._not_empty.notify()
            return True

    def dequeue(self, timeout: float = 1.0) -> AnalysisTask | None:
        """Get highest-priority task. Blocks up to timeout seconds."""
        with self._not_empty:
            while not self._heap and not self._shutdown:
                if not self._not_empty.wait(timeout):
                    return None  # Timed out
            if self._shutdown and not self._heap:
                return None
            task = heapq.heappop(self._heap)
            wait_ms = (time.monotonic() - task.enqueued_at) * 1000
            self.metrics.total_wait_ms += wait_ms
            self.metrics.processed += 1
            return task

    def dequeue_nowait(self) -> AnalysisTask | None:
        """Non-blocking dequeue."""
        with self._lock:
            if self._heap:
                task = heapq.heappop(self._heap)
                wait_ms = (time.monotonic() - task.enqueued_at) * 1000
                self.metrics.total_wait_ms += wait_ms
                self.metrics.processed += 1
                return task
            return None

    def size(self) -> int:
        with self._lock:
            return len(self._heap)

    def shutdown(self):
        """Signal workers to stop."""
        with self._not_empty:
            self._shutdown = True
            self._not_empty.notify_all()

    def reset(self):
        """Reset for reuse."""
        with self._not_empty:
            self._heap.clear()
            self._seen.clear()
            self._shutdown = False
            self.metrics = QueueMetrics()


# Global singleton
analysis_queue = AnalysisQueue()
