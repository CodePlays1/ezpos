"""Small in-process sliding-window rate limiter.

The licensing API is designed to run on loopback in a single process. If it is
deployed behind a proxy or with multiple workers, use a shared limiter (for
example Redis) instead.
"""

from __future__ import annotations

import time
from collections import deque

from fastapi import Request

from app.core.exceptions import RateLimitExceeded


class RateLimiter:
    def __init__(self, limit: int, window_seconds: float = 60.0) -> None:
        self.limit = max(0, int(limit))
        self.window_seconds = float(window_seconds)
        self._events: dict[str, deque[float]] = {}
        self._last_cleanup = time.monotonic()

    async def check(self, request: Request) -> None:
        if self.limit <= 0:
            return

        client = request.client.host if request.client else "unknown"
        now = time.monotonic()
        cutoff = now - self.window_seconds
        bucket = self._events.setdefault(client, deque())

        while bucket and bucket[0] <= cutoff:
            bucket.popleft()

        if len(bucket) >= self.limit:
            retry_after = int(self.window_seconds - (now - bucket[0])) + 1
            raise RateLimitExceeded(retry_after=retry_after)

        bucket.append(now)
        self._cleanup(now)

    def _cleanup(self, now: float) -> None:
        if now - self._last_cleanup < self.window_seconds:
            return
        self._last_cleanup = now
        cutoff = now - self.window_seconds
        stale = [
            key
            for key, bucket in self._events.items()
            if not bucket or bucket[-1] <= cutoff
        ]
        for key in stale:
            self._events.pop(key, None)
