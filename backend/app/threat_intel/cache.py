"""Threat Intelligence shared cache.

Key:  ``ti:cache:{provider}:{indicator_type}:{normalized_indicator}``
Value: JSON of the bounded TiLookup (already sanitized before storage).

Primary backend is Redis (shared across all workers). On Redis outage the cache
falls back to a bounded in-process store (documented limitation: per-process
only). Failures are never fatal: a cache error simply skips caching.
"""

from __future__ import annotations

import json
import logging

from app.threat_intel.models import TiLookup
from app.threat_intel.store import LocalStore, RedisStore

logger = logging.getLogger(__name__)

_DEFAULT_TTL_S = 3600
_LOCAL_MAX = 4096


class TiCache:
    def __init__(
        self,
        *,
        ttl_s: int | None = None,
        local_max: int = _LOCAL_MAX,
        redis: RedisStore | None = None,
        local: LocalStore | None = None,
    ) -> None:
        self._ttl = ttl_s if ttl_s is not None else _DEFAULT_TTL_S
        self._redis = redis if redis is not None else RedisStore()
        self._local = local if local is not None else LocalStore(max_entries=local_max)

    @staticmethod
    def key(provider: str, indicator_type: str, indicator: str) -> str:
        return f"ti:cache:{provider}:{indicator_type}:{indicator}"

    def get(self, provider: str, indicator_type: str, indicator: str) -> TiLookup | None:
        key = self.key(provider, indicator_type, indicator)
        raw = self._safe_get(key)
        if raw is None:
            return None
        try:
            payload = json.loads(raw)
            return TiLookup.model_validate(payload)
        except (ValueError, TypeError) as exc:
            logger.warning("TI_CACHE corrupt value key=%s", key)
            return None

    def set(self, lookup: TiLookup, ttl_s: int | None = None) -> None:
        key = self.key(lookup.provider, lookup.indicator_type, lookup.indicator)
        try:
            payload = json.dumps(lookup.model_dump(), ensure_ascii=False, default=str)
        except (TypeError, ValueError):
            return
        ttl = ttl_s if ttl_s is not None else self._ttl
        self._safe_set(key, ttl, payload)

    def _safe_get(self, key: str) -> str | None:
        try:
            return self._redis.get(key)
        except Exception as exc:  # noqa: BLE001 - fallback, never fatal
            logger.warning("TI_CACHE redis_get_failed key=%s err=%s", key, exc)
        try:
            return self._local.get(key)
        except Exception:  # noqa: BLE001
            return None
        return None

    def _safe_set(self, key: str, ttl: int, payload: str) -> None:
        try:
            self._redis.setex(key, ttl, payload)
            return
        except Exception as exc:  # noqa: BLE001
            logger.warning("TI_CACHE redis_set_failed key=%s err=%s", key, exc)
        try:
            self._local.setex(key, ttl, payload)
        except Exception:  # noqa: BLE001
            pass