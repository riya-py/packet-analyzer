"""
Port of include/thread_safe_queue.h

Thread-safe queue for passing packets between threads.
Used for: Reader -> LB -> FP communication.

Python's collections.deque + threading.Condition give us the same
push()-blocks-if-full / pop()-blocks-if-empty / shutdown-wakes-everyone
semantics as the original std::mutex + std::condition_variable design.
"""

from __future__ import annotations

import threading
from collections import deque
from typing import Generic, Optional, TypeVar

T = TypeVar("T")


class ThreadSafeQueue(Generic[T]):
    def __init__(self, max_size: int = 10000) -> None:
        self._queue: deque = deque()
        self._max_size = max_size
        self._shutdown = False

        self._lock = threading.Lock()
        self._not_empty = threading.Condition(self._lock)
        self._not_full = threading.Condition(self._lock)

    def push(self, item: T) -> None:
        """Push item to queue (blocks if full)."""
        with self._lock:
            while len(self._queue) >= self._max_size and not self._shutdown:
                self._not_full.wait()

            if self._shutdown:
                return

            self._queue.append(item)
            self._not_empty.notify()

    def try_push(self, item: T) -> bool:
        """Try to push without blocking."""
        with self._lock:
            if len(self._queue) >= self._max_size or self._shutdown:
                return False
            self._queue.append(item)
            self._not_empty.notify()
            return True

    def pop(self) -> Optional[T]:
        """Pop item from queue (blocks if empty)."""
        with self._lock:
            while not self._queue and not self._shutdown:
                self._not_empty.wait()

            if not self._queue:
                return None

            item = self._queue.popleft()
            self._not_full.notify()
            return item

    def pop_with_timeout(self, timeout_seconds: float) -> Optional[T]:
        """Pop with timeout (timeout in seconds, e.g. 0.1 for 100ms)."""
        with self._lock:
            deadline_ok = self._not_empty.wait_for(
                lambda: bool(self._queue) or self._shutdown, timeout=timeout_seconds
            )

            if not deadline_ok:
                return None  # Timeout

            if not self._queue:
                return None

            item = self._queue.popleft()
            self._not_full.notify()
            return item

    def empty(self) -> bool:
        with self._lock:
            return not self._queue

    def size(self) -> int:
        with self._lock:
            return len(self._queue)

    def shutdown(self) -> None:
        """Signal shutdown (wake up all waiting threads)."""
        with self._lock:
            self._shutdown = True
            self._not_empty.notify_all()
            self._not_full.notify_all()

    def is_shutdown(self) -> bool:
        with self._lock:
            return self._shutdown
