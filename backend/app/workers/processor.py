import logging
import threading
import uuid

from redis.exceptions import RedisError

from app.core.config import settings
from app.db import repositories
from app.db.session import SessionLocal
from app.orchestrator.scanner import run_pipeline
from app.queue.service import (
    ack,
    enqueue_scan,
    ensure_group,
    read_new,
    reclaim_stale,
)

logger = logging.getLogger(__name__)


def _validate_scan_id(raw: str) -> uuid.UUID | None:
    try:
        return uuid.UUID(raw)
    except (ValueError, TypeError, AttributeError):
        return None


def handle_scan_job(scan_id_raw: str) -> str:
    """Process one queued job and persist a terminal scan state.

    Returns an outcome used for acknowledgment decisions:
      processed - scan reached COMPLETED or FAILED -> safe to XACK
      skipped   - duplicate/stale/terminal delivery -> safe to XACK (no-op)
      dropped   - malformed job (poison message) -> safe to XACK (discard)
      deferred  - could not persist any state -> leave unacked (redeliver)

    Duplicate delivery is safe: only QUEUED scans (or PROCESSING scans whose
    lease expired after a worker crash) are claimed; a second delivery of the
    same job then finds the scan no longer claimable and is acknowledged as a
    no-op.
    """
    scan_id = _validate_scan_id(scan_id_raw)
    if scan_id is None:
        logger.warning("QUEUE_ERROR malformed_scan_id value=%r", scan_id_raw)
        return "dropped"

    db = None
    try:
        db = SessionLocal()
        scan = repositories.get_processable(
            db, scan_id, lease_grace_s=settings.redis_visibility_timeout_s
        )
        if scan is None:
            logger.info("SCAN_DEQUEUED skip_duplicate scan_id=%s", scan_id)
            return "skipped"

        repositories.purge_partial_results(db, scan)
        repositories.mark_processing(db, scan)
        logger.info("SCAN_STARTED scan_id=%s", scan_id)
        try:
            run_pipeline(db, scan)
            logger.info("SCAN_COMPLETED scan_id=%s", scan_id)
        except Exception as exc:  # noqa: BLE001 - worker must not die
            logger.exception("SCAN_FAILED scan_id=%s", scan_id)
            repositories.fail(db, scan, str(exc))
        return "processed"
    except Exception as exc:  # noqa: BLE001 - cannot persist any terminal state
        logger.exception("WORKER_ERROR scan_id=%s", scan_id)
        return "deferred"
    finally:
        if db is not None:
            db.close()


class ScanWorker:
    """Bounded Redis Stream consumers driving the EXISTING scan pipeline.

    Replaces the old DB-poll dispatch (see DECISIONS.md D-14). Each of the
    ``worker_max_threads`` threads is one consumer of the queue group; new jobs
    are read with blocking ``XREADGROUP``, jobs of crashed workers are
    reclaimed with ``XAUTOCLAIM``, and a job is acknowledged only after its
    scan reached a terminal state (or was a confirmed no-op duplicate).
    """

    def __init__(self) -> None:
        self._stop = threading.Event()
        self._activity_lock = threading.Lock()
        self._active_consumers: set[str] = set()
        self._threads = [
            threading.Thread(
                target=self._loop,
                name=f"scan-consumer-{i}",
                args=(f"consumer-{i}",),
                daemon=True,
            )
            for i in range(max(1, settings.worker_max_threads))
        ]

    def start(self) -> None:
        try:
            ensure_group()
        except RedisError:
            # Workers below will keep retrying with a bounded backoff.
            logger.exception("QUEUE_ERROR ensure_group")
        try:
            self._rescue_queued()
        except RedisError:
            logger.exception("QUEUE_ERROR rescue_queued")
        for t in self._threads:
            t.start()
        logger.info("redis scan worker started (%d consumers)", len(self._threads))

    def stop(self) -> None:
        self._stop.set()

    def snapshot(self) -> dict[str, int]:
        with self._activity_lock:
            return {"active": len(self._active_consumers)}

    def _rescue_queued(self) -> None:
        """Re-enqueue every QUEUED scan at startup (guarantee no stuck jobs).

        Safe: any duplicate copy already in the stream is acknowledged as a
        no-op by the claim logic.
        """
        db = SessionLocal()
        try:
            pending = repositories.stale_queued(db)
            for scan in pending:
                enqueue_scan(scan.id)
            if pending:
                logger.info(
                    "rescue sweep re-enqueued %d queued scan(s)", len(pending)
                )
        finally:
            db.close()

    def _loop(self, consumer: str) -> None:
        while not self._stop.is_set():
            try:
                new_entries = read_new(consumer)
                if new_entries:
                    for message_id, fields in new_entries:
                        self._handle(consumer, message_id, fields)
                    continue
                # No new record: redeliver stale in-flight jobs (crashed worker).
                for message_id, fields in reclaim_stale(consumer):
                    self._handle(consumer, message_id, fields)
            except RedisError as exc:
                if "NOGROUP" in str(exc):
                    # Self-heal: consumer group was recreated/missing (e.g. the
                    # backend booted before Redis or the stream was flushed).
                    try:
                        ensure_group()
                    except RedisError:
                        logger.exception("QUEUE_ERROR ensure_group consumer=%s", consumer)
                        self._stop.wait(settings.redis_backoff_s)
                    continue
                logger.exception("QUEUE_ERROR consumer=%s", consumer)
                self._stop.wait(settings.redis_backoff_s)
            except Exception:  # noqa: BLE001 - consumer must not die
                logger.exception("WORKER_ERROR consumer=%s", consumer)
                self._stop.wait(settings.redis_backoff_s)

    def _handle(self, consumer: str, message_id: str, fields: dict) -> None:
        with self._activity_lock:
            self._active_consumers.add(consumer)
        try:
            outcome = handle_scan_job(str(fields.get("scan_id", "")))
        finally:
            with self._activity_lock:
                self._active_consumers.discard(consumer)
        if outcome in ("processed", "skipped", "dropped"):
            try:
                ack(message_id)
                logger.debug(
                    "queue ack consumer=%s message=%s outcome=%s",
                    consumer,
                    message_id,
                    outcome,
                )
            except RedisError:
                logger.exception(
                    "QUEUE_ERROR ack_failed consumer=%s message=%s",
                    consumer,
                    message_id,
                )


worker = ScanWorker()
