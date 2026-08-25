from __future__ import annotations

import logging
import threading
from collections import OrderedDict, deque
from time import time

from fastapi import HTTPException, Request

from ..config import get_settings
from .request_context import client_ip

settings = get_settings()
logger = logging.getLogger(__name__)

try:
    import redis
except ModuleNotFoundError:  # pragma: no cover - optional dependency in tests/dev
    redis = None


class RateLimitBackend:
    def hit(self, bucket: str, key: str, limit: int, window_seconds: int) -> None:
        raise NotImplementedError

    def clear(self) -> None:
        return None


class MemoryRateLimitBackend(RateLimitBackend):
    def __init__(self, max_buckets: int | None = None) -> None:
        self._lock = threading.Lock()
        self._max_buckets = max(1, max_buckets or settings.rate_limit_memory_max_buckets)
        self._buckets: OrderedDict[str, deque[float]] = OrderedDict()

    def _prune_expired_locked(self, now: float) -> None:
        empty_keys: list[str] = []
        for bucket_key, entries in self._buckets.items():
            newest_window = bucket_key.rsplit(":", 1)[-1]
            try:
                window_seconds = int(newest_window)
            except ValueError:
                window_seconds = 0
            cutoff = now - window_seconds
            while entries and entries[0] <= cutoff:
                entries.popleft()
            if not entries:
                empty_keys.append(bucket_key)
        for bucket_key in empty_keys:
            self._buckets.pop(bucket_key, None)

    def _bucket_key(self, bucket: str, key: str, window_seconds: int) -> str:
        return f"{bucket}:{key}:{window_seconds}"

    def hit(self, bucket: str, key: str, limit: int, window_seconds: int) -> None:
        now = time()
        bucket_key = self._bucket_key(bucket, key, window_seconds)
        cutoff = now - window_seconds
        with self._lock:
            self._prune_expired_locked(now)
            entries = self._buckets.get(bucket_key)
            if entries is None:
                while len(self._buckets) >= self._max_buckets:
                    self._buckets.popitem(last=False)
                entries = deque()
                self._buckets[bucket_key] = entries
            else:
                self._buckets.move_to_end(bucket_key)
            while entries and entries[0] <= cutoff:
                entries.popleft()
            if len(entries) >= limit:
                raise HTTPException(status_code=429, detail="rate limit exceeded")
            entries.append(now)

    def clear(self) -> None:
        with self._lock:
            self._buckets.clear()


class RedisRateLimitBackend(RateLimitBackend):
    def __init__(self, url: str) -> None:
        if redis is None:
            raise RuntimeError("redis package is not installed")
        self._client = redis.Redis.from_url(url, decode_responses=True)

    def hit(self, bucket: str, key: str, limit: int, window_seconds: int) -> None:
        bucket_key = f"opnhub:ratelimit:{bucket}:{key}"
        try:
            count = int(self._client.incr(bucket_key))
            if count == 1:
                self._client.expire(bucket_key, window_seconds)
        except Exception as exc:  # pragma: no cover - depends on external redis
            logger.warning(
                "Redis rate limit backend unavailable, failing closed: %s", exc
            )
            raise HTTPException(
                status_code=503, detail="rate limiting unavailable"
            ) from exc
        if count > limit:
            raise HTTPException(status_code=429, detail="rate limit exceeded")

    def clear(self) -> None:
        return None


class EdgeRateLimitBackend(RateLimitBackend):
    def hit(self, bucket: str, key: str, limit: int, window_seconds: int) -> None:
        return None


class RateLimiter:
    def __init__(self) -> None:
        self._backend = self._build_backend()

    def _build_backend(self) -> RateLimitBackend:
        backend = settings.rate_limit_backend.strip().lower()
        if backend == "redis":
            if not settings.rate_limit_redis_url:
                raise RuntimeError(
                    "RATE_LIMIT_REDIS_URL is required when RATE_LIMIT_BACKEND=redis"
                )
            return RedisRateLimitBackend(settings.rate_limit_redis_url)
        if backend == "edge":
            return EdgeRateLimitBackend()
        return MemoryRateLimitBackend()

    def hit(self, bucket: str, key: str, limit: int, window_seconds: int) -> None:
        self._backend.hit(bucket, key, limit, window_seconds)

    def clear(self) -> None:
        self._backend.clear()


rate_limiter = RateLimiter()


def apply_rate_limit(
    request: Request, bucket: str, identifier: str, limit: int, window_seconds: int
) -> None:
    key = f"{client_ip(request)}:{identifier}"
    rate_limiter.hit(bucket, key, limit, window_seconds)
