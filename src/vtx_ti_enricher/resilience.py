"""Async resilience primitives: Token Bucket, Circuit Breaker, Jitter, and Singleflight."""

from __future__ import annotations

import asyncio
import secrets
import time
from collections.abc import Awaitable, Callable
from enum import Enum
from typing import Generic, TypeVar

T = TypeVar("T")


def compute_backoff_seconds(
    attempt: int,
    base_delay: float = 0.2,
    max_delay: float = 4.0,
    retry_after: float | None = None,
) -> float:
    """Compute Retry-After-aware exponential backoff with full jitter (Bandit-clean)."""
    if retry_after is not None and retry_after > 0:
        return min(retry_after, max_delay)
    ceiling = min(max_delay, max(0.01, base_delay) * (2 ** max(0, attempt - 1)))
    jitter_factor = secrets.randbelow(1000) / 1000.0
    return max(0.005, round(ceiling * (0.25 + 0.75 * jitter_factor), 4))


class AsyncTokenBucket:
    """Non-blocking asyncio token bucket with shared Retry-After penalty window."""

    def __init__(self, rate_per_sec: float = 5.0, burst: int = 5) -> None:
        self.rate_per_sec = max(0.1, rate_per_sec)
        self.capacity = float(max(1, burst))
        self._tokens = self.capacity
        self._updated_at = time.monotonic()
        self._blocked_until = 0.0
        self._lock = asyncio.Lock()

    async def penalize(self, delay_seconds: float) -> None:
        """Pause outbound acquisitions globally for this provider after HTTP 429."""
        if delay_seconds <= 0:
            return
        async with self._lock:
            target = time.monotonic() + delay_seconds
            if target > self._blocked_until:
                self._blocked_until = target
            self._tokens = 0.0

    async def acquire(self) -> None:
        """Wait without holding the lock until a token is available."""
        while True:
            async with self._lock:
                now = time.monotonic()
                if now < self._blocked_until:
                    wait_time = self._blocked_until - now
                else:
                    elapsed = now - self._updated_at
                    self._tokens = min(self.capacity, self._tokens + elapsed * self.rate_per_sec)
                    self._updated_at = now
                    if self._tokens >= 1.0:
                        self._tokens -= 1.0
                        return
                    wait_time = (1.0 - self._tokens) / self.rate_per_sec
            await asyncio.sleep(wait_time)


class CircuitState(str, Enum):
    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"


class AsyncCircuitBreaker:
    """Per-provider async Circuit Breaker protecting the pool from degraded upstreams."""

    def __init__(
        self,
        failure_threshold: int = 5,
        recovery_timeout: float = 30.0,
        half_open_max_calls: int = 1,
    ) -> None:
        self.failure_threshold = max(1, failure_threshold)
        self.recovery_timeout = max(0.05, recovery_timeout)
        self.half_open_max_calls = max(1, half_open_max_calls)
        self._state = CircuitState.CLOSED
        self._consecutive_failures = 0
        self._opened_at = 0.0
        self._half_open_inflight = 0
        self._lock = asyncio.Lock()

    @property
    def state(self) -> CircuitState:
        return self._state

    async def allow_request(self) -> bool:
        async with self._lock:
            if self._state == CircuitState.CLOSED:
                return True
            if self._state == CircuitState.OPEN:
                if (time.monotonic() - self._opened_at) >= self.recovery_timeout:
                    self._state = CircuitState.HALF_OPEN
                    self._half_open_inflight = 1
                    return True
                return False
            if self._half_open_inflight < self.half_open_max_calls:
                self._half_open_inflight += 1
                return True
            return False

    async def record_success(self) -> None:
        async with self._lock:
            self._consecutive_failures = 0
            self._half_open_inflight = 0
            self._state = CircuitState.CLOSED

    async def record_failure(self) -> None:
        async with self._lock:
            if self._state == CircuitState.HALF_OPEN:
                self._half_open_inflight = max(0, self._half_open_inflight - 1)
                self._state = CircuitState.OPEN
                self._opened_at = time.monotonic()
                return
            self._consecutive_failures += 1
            if self._consecutive_failures >= self.failure_threshold:
                self._state = CircuitState.OPEN
                self._opened_at = time.monotonic()


class AsyncSingleflight(Generic[T]):
    """Deduplicates identical concurrent in-flight lookups across coroutines."""

    def __init__(self) -> None:
        self._inflight: dict[str, asyncio.Future[T]] = {}
        self._lock = asyncio.Lock()
        self.coalesced_hits = 0

    async def do(self, key: str, fn: Callable[[], Awaitable[T]]) -> T:
        loop = asyncio.get_running_loop()
        owner = False
        async with self._lock:
            fut = self._inflight.get(key)
            if fut is None:
                fut = loop.create_future()
                self._inflight[key] = fut
                owner = True
            else:
                self.coalesced_hits += 1

        if not owner:
            return await asyncio.shield(fut)

        try:
            result = await fn()
        except BaseException as exc:
            if not fut.done():
                fut.set_exception(exc)
                fut.exception()
            raise
        else:
            if not fut.done():
                fut.set_result(result)
            return result
        finally:
            async with self._lock:
                if self._inflight.get(key) is fut:
                    del self._inflight[key]
