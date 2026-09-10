"""Centralized, Redis-backed rate limiter for external TI providers.

Guarantees required by the TI design (DECISIONS.md D-17):

- minimum request spacing (atomic SET NX EX),
- rolling per-minute limiter and daily counter (INCR + EXPIRE),
- shared by every worker: there is NEVER one limiter per worker - the default
  ``RateLimiter`` instance is a module singleton backed by the shared Redis
  client, so concurrent worker threads/processes enforce one budget,
- bounded: a "not allowed" answer never loops; the caller records
  ``rate_limited`` and moves on,
- fail-safe: if Redis is unreachable it falls back to a process-wide in-memory
  store (documented limitation: per-process only, restored automatically once
  Redis is reachable).

This limiter meters outgoing requests ONLY - it is never involved in scoring,
findings or verdicts.
"""

from __future__ import annotations

import logging
import math
import time
import uuid

from app.threat_intel.store import LocalStore, RedisStore, TiStore

logger = logging.getLogger(__name__)


class RateLimiter:
    def __init__(
        self,
        *,
        redis: TiStore | None = None,
        local: TiStore | None = None,
    ) -> None:
        self._redis = redis if redis is not None else RedisStore()
        self._local = local if local is not None else LocalStore()

    def spacing_s_for(self, per_minute: int, configured_spacing: float) -> float:
        """Minimum spacing: explicit value, else ceil(60 / per_minute)."""
        if configured_spacing and configured_spacing > 0:
            return float(configured_spacing)
        return max(1.0, math.ceil(60.0 / max(1, int(per_minute))))

    def acquire(
        self,
        provider: str,
        *,
        per_minute: int,
        per_day: int,
        spacing_s: float,
    ) -> tuple[bool, int]:
        """Return (allowed, retry_after_s).

        ``spacing_s`` is the effective minimum spacing (already computed by the
        caller via :meth:`spacing_s_for`). A denied answer carries the number of
        seconds after which a retry is most likely to succeed.
        """
        now = int(time.time())
        min_key = f"ti:rl:{provider}:min:{now // 60}"
        day_key = f"ti:rl:{provider}:day:{now // 86400}"
        space_key = f"ti:rl:{provider}:space"
        token = f"{time.time_ns()}-{uuid.uuid4().hex[:8]}"

        try:
            return self._acquire_redis(
                provider, min_key, day_key, space_key, token,
                per_minute=per_minute, per_day=per_day, spacing_s=spacing_s,
            )
        except Exception as exc:  # noqa: BLE001 - Redis outage: local fallback
            logger.warning("TI_LIMIT redis_degraded provider=%s err=%s", provider, exc)
        try:
            return self._acquire_store(
                self._local, min_key, day_key, space_key, token,
                per_minute=per_minute, per_day=per_day, spacing_s=spacing_s,
            )
        except Exception as exc:  # noqa: BLE001 - never fatal
            logger.error("TI_LIMIT local_failed provider=%s err=%s", provider, exc)
            return False, int(spacing_s or 1)

    def _acquire_redis(
        self, provider, min_key, day_key, space_key, token,
        *, per_minute, per_day, spacing_s,
    ) -> tuple[bool, int]:
        return self._acquire_store(
            self._redis, min_key, day_key, space_key, token,
            per_minute=per_minute, per_day=per_day, spacing_s=spacing_s,
        )

    @staticmethod
    def _acquire_store(
        store: TiStore, min_key, day_key, space_key, token,
        *, per_minute, per_day, spacing_s,
    ) -> tuple[bool, int]:
        # 1) Minimum spacing gate (atomic). Only one caller gets through.
        if not store.set_nx(space_key, max(1, int(spacing_s * 2 + 1)), token):
            remaining = store.ttl(space_key)
            return False, max(1, remaining) if remaining and remaining > 0 else 1
        # 2) Rolling minute window.
        minute_count = store.incr(min_key)
        if minute_count <= 1:
            store.expire(min_key, 60)
        if minute_count > per_minute:
            return False, int(spacing_s or 1)
        # 3) Daily counter.
        day_count = store.incr(day_key)
        if day_count <= 1:
            store.expire(day_key, 86400)
        if day_count > per_day:
            return False, int(spacing_s or 1)
        return True, 0


# Module-level singleton: ALL workers share one limiter (centralized budget).
_default_limiter: RateLimiter | None = None


def default_limiter() -> RateLimiter:
    global _default_limiter
    if _default_limiter is None:
        _default_limiter = RateLimiter()
    return _default_limiter