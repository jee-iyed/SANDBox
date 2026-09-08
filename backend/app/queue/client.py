"""Lazy Redis client shared by the API (enqueue) and the workers (consume).

Connection parameters come from ``app.core.config.settings`` (REDIS_URL or
REDIS_HOST/REDIS_PORT/REDIS_DB + optional REDIS_USERNAME/REDIS_PASSWORD).
No credentials are ever hardcoded. Reserved solely for job metadata: the queue
carries ``scan_id`` only, never file contents.
"""

import logging

from redis import Redis

from app.core.config import settings

logger = logging.getLogger(__name__)

_client: Redis | None = None


def get_redis() -> Redis:
    """Return the process-wide Redis client, creating it lazily."""
    global _client
    if _client is None:
        _client = Redis.from_url(
            settings.redis_connection_url,
            username=settings.redis_username,
            password=settings.redis_password,
            decode_responses=True,
            socket_connect_timeout=settings.redis_backoff_s,
            # Must exceed the blocking read window (BLOCK redis_block_timeout_ms)
            # so a long-parked XREADGROUP does not hit the socket timeout.
            socket_timeout=(settings.redis_block_timeout_ms / 1000.0) + 2.0,
            retry_on_timeout=False,
            health_check_interval=30,
        )
        logger.debug("redis client created url=%s", settings.redis_connection_url)
    return _client


def close_redis() -> None:
    """Release the shared client (used at shutdown and by tests)."""
    global _client
    if _client is not None:
        _client.close()
        _client = None