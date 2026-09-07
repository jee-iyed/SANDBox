import logging
import threading
import time

from app.core.config import settings
from app.db import repositories
from app.db.session import SessionLocal
from app.orchestrator.scanner import run_pipeline

logger = logging.getLogger(__name__)


class ScanWorker:
    """MVP background worker: polls the DB for QUEUED scans and drives the pipeline.

    Rationale & limitations: see DECISIONS.md (§2.5). Simple, reliable, no extra
    infra. Not durable across process restarts and not horizontally distributable;
    if those requirements appear, migrate to Celery + Redis.
    """

    def __init__(self) -> None:
        self._stop = threading.Event()
        self._threads = [
            threading.Thread(target=self._loop, name=f"scan-worker-{i}", daemon=True)
            for i in range(max(1, settings.worker_max_threads))
        ]

    def start(self) -> None:
        for t in self._threads:
            t.start()
        logger.info("scan worker started (%d threads)", len(self._threads))

    def stop(self) -> None:
        self._stop.set()

    def _loop(self) -> None:
        while not self._stop.is_set():
            # Do not inject an idle-poll delay between queued jobs.  Claiming
            # remains transactional (FOR UPDATE SKIP LOCKED), while an empty
            # queue still uses a bounded, interruptible wait.
            if not self._tick():
                self._stop.wait(settings.worker_poll_interval_s)

    def _tick(self) -> bool:
        db = SessionLocal()
        try:
            scan = repositories.claim_next_queued(db)
            if scan is None:
                return False
            repositories.mark_processing(db, scan)
            try:
                run_pipeline(db, scan)
            except Exception as exc:  # noqa: BLE001 - worker must not die
                logger.exception("scan %s failed", scan.id)
                repositories.fail(db, scan, str(exc))
            return True
        finally:
            db.close()


worker = ScanWorker()
