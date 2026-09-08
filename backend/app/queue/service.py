"""Reliable scan job queue on a Redis Stream (+ consumer group).

Contract
--------
* Jobs are JSON-light entries carrying ONLY ``{scan_id: "<uuid>"}``. Files and
  persistent scan state stay in PostgreSQL / storage - never in Redis.
* Reliability: the consumer-group pending-entries list (PEL) tracks in-flight
  jobs; ``XAUTOCLAIM`` redelivers jobs of crashed workers after a visibility
  timeout; ``XACK`` removes a job only after its scan reached a terminal state
  or was confirmed non-actionable. See DECISIONS.md D-14.
"""

import logging

from redis.exceptions import ResponseError

from app.core.config import settings
from app.queue.client import get_redis

logger = logging.getLogger(__name__)


def stream_name() -> str:
    return settings.redis_queue_name


def group_name() -> str:
    return settings.redis_consumer_group


def ensure_group() -> None:
    """Create the consumer group idempotently (stream created on demand)."""
    redis = get_redis()
    try:
        redis.xgroup_create(stream_name(), group_name(), id="0", mkstream=True)
        logger.info(
            "queue group ensured stream=%s group=%s", stream_name(), group_name()
        )
    except ResponseError as exc:
        if "BUSYGROUP" not in str(exc):
            raise


def enqueue_scan(scan_id) -> str:
    """Push a job metadata entry; returns the Redis message id.

    Raises ``redis.exceptions.RedisError`` when Redis is unavailable so the
    API can surface a clean 503 (the caller re-enqueues / cleans up).
    """
    redis = get_redis()
    message_id = redis.xadd(
        stream_name(),
        {"scan_id": str(scan_id)},
        maxlen=settings.redis_stream_maxlen,
        approximate=True,
    )
    logger.info("SCAN_ENQUEUED scan_id=%s message=%s", scan_id, message_id)
    return message_id


def read_new(consumer: str, count: int = 1) -> list[tuple[str, dict]]:
    """Blocking read of NEW records assigned to ``consumer``.

    Returns ``[(message_id, fields)]``; empty list when the block window
    elapsed with no new record.
    """
    redis = get_redis()
    response = redis.xreadgroup(
        group_name(),
        consumer,
        {stream_name(): ">"},
        count=count,
        block=settings.redis_block_timeout_ms,
    )
    entries: list[tuple[str, dict]] = []
    for _sname, messages in response or []:
        for message_id, fields in messages:
            entries.append((message_id, dict(fields)))
    return entries


def reclaim_stale(consumer: str, count: int = 1) -> list[tuple[str, dict]]:
    """Requeue PEL records left idle past the visibility timeout.

    Used when there are no new records so crashed workers' jobs are
    redelivered. ``XAUTOCLAIM`` is atomic, so concurrent reclaims never get
    the same record twice.
    """
    redis = get_redis()
    min_idle_ms = settings.redis_visibility_timeout_s * 1000
    _next_start, claimed, _deleted = redis.xautoclaim(
        stream_name(),
        group_name(),
        consumer,
        min_idle_time=min_idle_ms,
        start_id="0-0",
        count=count,
    )
    return [(message_id, dict(fields)) for message_id, fields in claimed]


def ack(message_id: str) -> None:
    """Acknowledge a job after its scan reached a terminal state."""
    redis = get_redis()
    redis.xack(stream_name(), group_name(), message_id)
    logger.debug("QUEUE_ACK message=%s", message_id)


def queue_len() -> int:
    """Current number of records in the dispatch stream (observability/tests)."""
    return get_redis().xlen(stream_name())