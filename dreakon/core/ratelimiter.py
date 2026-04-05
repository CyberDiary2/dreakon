import asyncio
import time
import random
from collections import defaultdict


class TokenBucket:
    """Per-host async token bucket with jitter."""

    def __init__(self, rate: float, capacity: int):
        self.rate = rate        # tokens per second
        self.capacity = capacity
        self._tokens = capacity
        self._last_refill = time.monotonic()
        self._lock = asyncio.Lock()

    async def acquire(self):
        async with self._lock:
            now = time.monotonic()
            elapsed = now - self._last_refill
            self._tokens = min(self.capacity, self._tokens + elapsed * self.rate)
            self._last_refill = now

            if self._tokens < 1:
                wait = (1 - self._tokens) / self.rate
                await asyncio.sleep(wait)
                self._tokens = 0
            else:
                self._tokens -= 1

        # Jitter to avoid thundering herd
        await asyncio.sleep(random.uniform(0.05, 0.2))


class RateLimiterRegistry:
    """Global registry of per-host rate limiters."""

    def __init__(self):
        self._buckets: dict[str, TokenBucket] = {}
        self._error_counts: dict[str, int] = defaultdict(int)
        self._lock = asyncio.Lock()

    async def get(self, host: str, rate: float = 10.0, capacity: int = 20) -> TokenBucket:
        async with self._lock:
            if host not in self._buckets:
                self._buckets[host] = TokenBucket(rate, capacity)
            return self._buckets[host]

    async def record_error(self, host: str):
        """Halve rate after sustained errors."""
        async with self._lock:
            self._error_counts[host] += 1
            if self._error_counts[host] >= 5 and host in self._buckets:
                bucket = self._buckets[host]
                bucket.rate = max(0.5, bucket.rate / 2)
                self._error_counts[host] = 0

    async def record_success(self, host: str):
        async with self._lock:
            self._error_counts[host] = max(0, self._error_counts[host] - 1)


rate_limiter = RateLimiterRegistry()
