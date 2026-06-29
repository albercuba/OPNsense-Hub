from __future__ import annotations

import threading
from collections import defaultdict, deque
from time import time

from fastapi import HTTPException, Request


class RateLimiter:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._buckets: dict[str, deque[float]] = defaultdict(deque)

    def hit(self, bucket: str, key: str, limit: int, window_seconds: int) -> None:
        now = time()
        bucket_key = f"{bucket}:{key}"
        cutoff = now - window_seconds
        with self._lock:
            entries = self._buckets[bucket_key]
            while entries and entries[0] <= cutoff:
                entries.popleft()
            if len(entries) >= limit:
                raise HTTPException(status_code=429, detail="rate limit exceeded")
            entries.append(now)

    def clear(self) -> None:
        with self._lock:
            self._buckets.clear()


rate_limiter = RateLimiter()


def client_ip(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        first = forwarded.split(",", 1)[0].strip()
        if first:
            return first
    if request.client and request.client.host:
        return request.client.host
    return "unknown"


def apply_rate_limit(
    request: Request, bucket: str, identifier: str, limit: int, window_seconds: int
) -> None:
    key = f"{client_ip(request)}:{identifier}"
    rate_limiter.hit(bucket, key, limit, window_seconds)
