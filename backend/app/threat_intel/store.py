"""Tiny key/value adapter used by the TI cache and TI rate limiter.

Primary backend is Redis (shared by every worker so limits/cache are enforced
system-wide, see DECISIONS.md D-17). If Redis is unreachable the adapters
fall back to a bounded, thread-safe in-process store so TI stays fail-safe;
the documented limitation of the in-process fallback is that it is per-process
only (a multi-process deployment would need Redis back to share state).
"""

from __future__ import annotations

import threading
import time

from app.queue.client import get_redis


class TiStore:
    """Interface: subset of Redis commands used by cache + limiter."""

    def get(self, key: str) -> str | None:  # pragma: no cover - interface
        raise NotImplementedError

    def setex(self, key: str, ttl_s: int, value: str) -> None:  # pragma: no cover
        raise NotImplementedError

    def set_nx(self, key: str, ttl_s: int, value: str) -> bool:  # pragma: no cover
        raise NotImplementedError

    def incr(self, key: str) -> int:  # pragma: no cover
        raise NotImplementedError

    def expire(self, key: str, ttl_s: int) -> None:  # pragma: no cover
        raise NotImplementedError

    def ttl(self, key: str) -> int:  # pragma: no cover
        raise NotImplementedError


class RedisStore(TiStore):
    """Redis-backed adapter (reuses the shared queue client)."""

    def get(self, key: str) -> str | None:
        value = get_redis().get(key)
        return value if value is not None else None

    def setex(self, key: str, ttl_s: int, value: str) -> None:
        get_redis().setex(key, ttl_s, value)

    def set_nx(self, key: str, ttl_s: int, value: str) -> bool:
        return bool(get_redis().set(key, value, ex=ttl_s, nx=True))

    def incr(self, key: str) -> int:
        return int(get_redis().incr(key) or 0)

    def expire(self, key: str, ttl_s: int) -> None:
        get_redis().expire(key, ttl_s)

    def ttl(self, key: str) -> int:
        return int(get_redis().ttl(key) or -2)


class LocalStore(TiStore):
    """Thread-safe in-process fallback store (bounded, evicted by expiry)."""

    def __init__(self, max_entries: int = 4096) -> None:
        self._max = max(64, int(max_entries))
        self._data: dict[str, tuple[str, float | None]] = {}
        self._lock = threading.Lock()

    def _purge_expired(self) -> None:
        now = time.monotonic()
        expired = [k for k, (_, exp) in self._data.items() if exp is not None and exp <= now]
        for key in expired:
            self._data.pop(key, None)

    def _trim(self) -> None:
        if len(self._data) >= self._max:
            # Evict oldest (dict preserves insertion order).
            for key in list(self._data.keys())[: max(1, len(self._data) - self._max + 1)]:
                self._data.pop(key, None)

    def get(self, key: str) -> str | None:
        with self._lock:
            entry = self._data.get(key)
            if entry is None:
                return None
            value, exp = entry
            if exp is not None and exp <= time.monotonic():
                self._data.pop(key, None)
                return None
            return value

    def setex(self, key: str, ttl_s: int, value: str) -> None:
        with self._lock:
            self._purge_expired()
            exp = time.monotonic() + ttl_s if ttl_s and ttl_s > 0 else None
            self._data[key] = (value, exp)
            self._trim()

    def set_nx(self, key: str, ttl_s: int, value: str) -> bool:
        with self._lock:
            self._purge_expired()
            if key in self._data:
                return False
            exp = time.monotonic() + ttl_s if ttl_s and ttl_s > 0 else None
            self._data[key] = (value, exp)
            self._trim()
            return True

    def incr(self, key: str) -> int:
        with self._lock:
            current = self._data.get(key)
            value = int(current[0]) if current else 0
            self._data[key] = (str(value + 1), current[1] if current else None)
            return value + 1

    def expire(self, key: str, ttl_s: int) -> None:
        with self._lock:
            current = self._data.get(key)
            if current is not None:
                self._data[key] = (current[0], time.monotonic() + ttl_s if ttl_s and ttl_s > 0 else None)

    def ttl(self, key: str) -> int:
        with self._lock:
            entry = self._data.get(key)
            if entry is None:
                return -2
            _, exp = entry
            if exp is None:
                return -1
            remaining = int(exp - time.monotonic())
            return remaining if remaining > 0 else -2