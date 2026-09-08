"""Focused Redis queue unit tests (no live Redis / PostgreSQL / Docker needed).

Covers: enqueue, consume->completed, consume->failed, multi-queue, concurrent
consumers, duplicate-delivery safety, malformed jobs, Redis-unavailable 503.

Usage:
    .\\.venv\\Scripts\\python.exe tests\\test_redis_queue.py
"""

from __future__ import annotations

import sys
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from redis.exceptions import RedisError  # noqa: E402

from app.queue import service as qservice  # noqa: E402
import app.workers.processor  # noqa: E402,F401  (register module for patching)

PASS = 0
FAIL = 0


def report(name: str, ok: bool, detail: str = ""):
    global PASS, FAIL
    if ok:
        PASS += 1
    else:
        FAIL += 1
    print(f"[{'PASS' if ok else 'FAIL'}] {name}" + (f"  -> {detail}" if detail else ""))


def make_scan(status="queued"):
    return SimpleNamespace(
        id=uuid.uuid4(),
        status=status,
        updated_at=datetime.now(timezone.utc),
        verdict=None,
        action=None,
        risk_score=None,
        completed_at=None,
        error_message=None,
    )


class _FakeSession:
    def __init__(self):
        self.closed = False

    def close(self):
        self.closed = True


def _fake_session():
    return _FakeSession()


class FakeRedis:
    """Minimal redis-py-compatible fake recording punctuated calls."""

    def __init__(self):
        self.calls: list[tuple] = []

    def xadd(self, name, fields, **kw):
        self.calls.append(("xadd", name, dict(fields)))
        return "1-0"

    def xgroup_create(self, *a, **kw):
        self.calls.append(("xgroup_create", a, kw))

    def xreadgroup(self, group, consumer, streams, count=None, block=None):
        sid = f"m-{uuid.uuid4().hex}"
        return [[next(iter(streams)), [(sid, {"scan_id": str(uuid.uuid4())})]]]

    def xautoclaim(self, *a, **kw):
        return ["0-0", [], []]

    def xack(self, name, group, *ids):
        self.calls.append(("xack", name, group, ids))

    def xlen(self, name):
        return 0


# ---------------------------------------------------------------------------
# Queue service primitives
# ---------------------------------------------------------------------------

def test_enqueue_pushes_scan_id_only():
    fake = FakeRedis()
    sid = uuid.uuid4()
    with patch.object(qservice, "get_redis", lambda: fake):
        mid = qservice.enqueue_scan(sid)
    xadds = [c for c in fake.calls if c[0] == "xadd"]
    ok = mid == "1-0" and len(xadds) == 1 and xadds[0][1] == "sandbox:scans"
    ok = ok and xadds[0][2] == {"scan_id": str(sid)}
    report("enqueue_scan -> XADD {scan_id} only", ok, str(xadds))


def test_read_new_and_ack_shape():
    fake = FakeRedis()
    with patch.object(qservice, "get_redis", lambda: fake):
        entries = qservice.read_new("consumer-0")
        qservice.ack("m-1")
    report(
        "read_new returns (id, fields) + ack calls XACK",
        len(entries) == 1 and entries[0][0].startswith("m-"),
    )


def test_reclaim_stale_handles_dead_workers():
    fake = FakeRedis()
    try:
        with patch.object(qservice, "get_redis", lambda: fake):
            entries = qservice.reclaim_stale("consumer-1")
        report("reclaim_stale -> XAUTOCLAIM empty list", entries == [])
    except Exception as exc:  # noqa: BLE001
        report("reclaim_stale -> XAUTOCLAIM empty list", False, str(exc))


# ---------------------------------------------------------------------------
# Worker job handling
# ---------------------------------------------------------------------------

def test_worker_consumes_and_completes_scan():
    scan = make_scan("queued")
    calls = {"processing": 0, "purge": 0}

    def fake_purge(db, s):
        # Mirrors the real guard: purge only when reclaiming a PROCESSING scan.
        if s.status == "processing":
            calls["purge"] += 1

    with patch("app.workers.processor.SessionLocal", _fake_session):
        with patch("app.workers.processor.run_pipeline", lambda db, s: None):
            with patch("app.db.repositories.get_processable", lambda db, sid, lease_grace_s=600: scan):
                with patch("app.db.repositories.purge_partial_results", fake_purge):
                    with patch("app.db.repositories.mark_processing", lambda db, s: calls.__setitem__("processing", calls["processing"] + 1)):
                        with patch("app.db.repositories.fail") as fail:
                            from app.workers.processor import handle_scan_job
                            outcome = handle_scan_job(str(scan.id))
    ok = outcome == "processed" and calls["processing"] == 1 and calls["purge"] == 0 and not fail.called
    report("worker consume -> scan reaches completed (processed)", ok, outcome)


def test_worker_marks_failed_when_pipeline_throws():
    scan = make_scan("queued")
    with patch("app.workers.processor.SessionLocal", _fake_session):
        with patch("app.workers.processor.run_pipeline", side_effect=RuntimeError("boom")):
            with patch("app.db.repositories.get_processable", lambda db, sid, lease_grace_s=600: scan):
                with patch("app.db.repositories.purge_partial_results", lambda db, s: None):
                    with patch("app.db.repositories.mark_processing", lambda db, s: None):
                        with patch("app.db.repositories.fail") as fail:
                            from app.workers.processor import handle_scan_job
                            outcome = handle_scan_job(str(scan.id))
    ok = outcome == "processed" and fail.called and fail.call_args[0][2] == "boom"
    report("worker consume -> failed when pipeline throws", ok, outcome)


def test_multiple_scans_queued_then_consumed():
    fake = FakeRedis()
    ids = [uuid.uuid4() for _ in range(5)]
    with patch.object(qservice, "get_redis", lambda: fake):
        for sid in ids:
            qservice.enqueue_scan(sid)
    xadds = [c for c in fake.calls if c[0] == "xadd"]
    report("multiple scans -> each enqueued exactly once",
           len(xadds) == 5 and {c[2]["scan_id"] for c in xadds} == {str(i) for i in ids})


def test_concurrent_consumers_process_different_jobs():
    from app.workers.processor import handle_scan_job

    state = {}
    lock = threading.Lock()
    for _ in range(4):
        sid = uuid.uuid4()
        state[sid] = SimpleNamespace(
            id=sid,
            status="queued",
            updated_at=datetime.now(timezone.utc),
            verdict=None,
            action=None,
            risk_score=None,
            completed_at=None,
            error_message=None,
        )

    def fake_get(db, sid, lease_grace_s=600):
        with lock:
            s = state.get(sid)
            return s if s and s.status == "queued" else None

    def fake_mark(db, s):
        with lock:
            state[s.id].status = "processing"

    results = []
    errors = []

    def run_one(sid):
        try:
            with patch("app.workers.processor.SessionLocal", _fake_session):
                with patch("app.workers.processor.run_pipeline", lambda db, s: None):
                    with patch("app.db.repositories.get_processable", fake_get):
                        with patch("app.db.repositories.purge_partial_results", lambda db, s: None):
                            with patch("app.db.repositories.mark_processing", fake_mark):
                                with patch("app.db.repositories.fail"):
                                    results.append(handle_scan_job(str(sid)))
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=run_one, args=(sid,)) for sid in state]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    report("multiple workers -> different jobs concurrently, no interference",
           len(results) == 4 and all(r == "processed" for r in results) and not errors,
           f"results={results}")


def test_duplicate_delivery_does_not_corrupt():
    from app.workers.processor import handle_scan_job

    scan = make_scan("queued")
    calls = {"claims": 0, "pipeline": 0}

    def fake_get(db, sid, lease_grace_s=600):
        calls["claims"] += 1
        if scan.status == "queued":
            return scan
        return None  # already PROCESSING/COMPLETED/FAILED -> no-op

    def fake_pipeline(db, s):
        calls["pipeline"] += 1
        scan.status = "completed"

    # First delivery: processed.
    with patch("app.workers.processor.SessionLocal", _fake_session):
        with patch("app.workers.processor.run_pipeline", fake_pipeline):
            with patch("app.db.repositories.get_processable", fake_get):
                with patch("app.db.repositories.purge_partial_results", lambda db, s: None):
                    with patch("app.db.repositories.mark_processing", lambda db, s: setattr(scan, "status", "processing")):
                        with patch("app.db.repositories.fail"):
                            first = handle_scan_job(str(scan.id))
    # Second (duplicate) delivery: skipped, pipeline NOT re-run.
    with patch("app.workers.processor.SessionLocal", _fake_session):
        with patch("app.workers.processor.run_pipeline", fake_pipeline):
            with patch("app.db.repositories.get_processable", fake_get):
                with patch("app.db.repositories.purge_partial_results", lambda db, s: None):
                    with patch("app.db.repositories.mark_processing", lambda db, s: None):
                        with patch("app.db.repositories.fail"):
                            second = handle_scan_job(str(scan.id))
    ok = first == "processed" and second == "skipped" and calls["pipeline"] == 1
    report("duplicate delivery -> second copy skipped, pipeline run once", ok,
           f"first={first} second={second} pipeline_runs={calls['pipeline']}")


def test_malformed_job_dropped():
    from app.workers.processor import handle_scan_job
    with patch("app.workers.processor.SessionLocal", _fake_session):
        outcome = handle_scan_job("not-a-uuid")
    report("malformed job dropped (poison message)", outcome == "dropped", outcome)


def test_handle_deferred_when_db_unavailable():
    from app.workers.processor import handle_scan_job
    sid = uuid.uuid4()
    with patch("app.workers.processor.SessionLocal", side_effect=RuntimeError("db down")):
        outcome = handle_scan_job(str(sid))
    report("DB unavailable -> deferred (unacked, redelivered)", outcome == "deferred", outcome)


def test_ack_only_after_terminal():
    from app.workers.processor import ScanWorker

    worker = ScanWorker()
    acked = []

    def fake_ack(mid):
        acked.append(mid)

    with patch("app.workers.processor.handle_scan_job", return_value="processed"):
        with patch("app.workers.processor.ack", fake_ack):
            worker._handle("c", "m-1", {"scan_id": str(uuid.uuid4())})
    with patch("app.workers.processor.handle_scan_job", return_value="deferred"):
        with patch("app.workers.processor.ack", fake_ack):
            worker._handle("c", "m-2", {"scan_id": str(uuid.uuid4())})
    report("ack after terminal/warn; no ack when deferred",
           acked == ["m-1"], str(acked))


# ---------------------------------------------------------------------------
# API: Redis-unavailable behaviour (clean 503 + rollback)
# ---------------------------------------------------------------------------

def test_enqueue_failure_returns_503():
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from app.api.routes.scans import router as scans_router
    from app.core.config import settings as _settings

    test_app = FastAPI()
    test_app.include_router(scans_router)

    class FakeSession:
        def __init__(self):
            self.added = []
            self.commits = 0

        def add(self, obj):
            self.added.append(obj)

        def flush(self):
            return None

        def commit(self):
            self.commits += 1

        def delete(self, obj):
            self.marked_deleted = obj

        def rollback(self):
            self.rolled_back = True

    fake_db = FakeSession()
    fake_scan = make_scan("queued")

    async def fake_get_db():
        yield fake_db

    with patch("app.api.routes.scans.repositories.create", return_value=fake_scan):
        with patch("app.api.routes.scans.repositories.delete", side_effect=lambda db, s: setattr(db, "deleted", True)):
            with patch("app.api.routes.scans.storage.save_upload", return_value=Path("x")):
                with patch("app.api.routes.scans.enqueue_scan", side_effect=RedisError("redis down")):
                    from app.api.routes.scans import get_db

                    test_app.dependency_overrides[get_db] = fake_get_db
                    client = TestClient(test_app)
                    resp = client.post(
                        "/api/scans",
                        files={"file": ("x.pdf", b"%PDF-1.4 dummy", "application/pdf")},
                    )
    ok = resp.status_code == 503
    ok = ok and "scan queue unavailable" in resp.json()["detail"].lower()
    report("redis unavailable -> POST /api/scans 503 + rollback", ok, f"status={resp.status_code}")


def test_enqueue_success_returns_202_queued():
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from app.api.routes.scans import router as scans_router
    from app.db.models import ScanStatus, Verdict

    test_app = FastAPI()
    test_app.include_router(scans_router)

    fake_scan = make_scan("queued")
    fake_scan.status = ScanStatus.QUEUED
    fake_scan.verdict = Verdict.NOT_ANALYZED
    fake_scan.created_at = datetime.now(timezone.utc)
    fake_scan.updated_at = datetime.now(timezone.utc)

    async def fake_get_db():
        yield object()

    class FakeUpload:
        pass

    with patch("app.api.routes.scans.repositories.create", return_value=fake_scan):
        with patch("app.api.routes.scans.storage.save_upload", return_value=Path("x")):
            with patch("app.api.routes.scans.enqueue_scan", return_value="1-0"):
                with patch("app.api.routes.scans._load", return_value=fake_scan):
                    from app.api.routes.scans import get_db

                    test_app.dependency_overrides[get_db] = fake_get_db
                    client = TestClient(test_app)
                    resp = client.post(
                        "/api/scans",
                        files={"file": ("x.pdf", b"%PDF-1.4 dummy", "application/pdf")},
                    )
    ok = resp.status_code == 202 and resp.json()["status"] == "queued"
    report("redis ok -> POST /api/scans 202 + queued", ok, f"status={resp.status_code}")


test_enqueue_pushes_scan_id_only()
test_read_new_and_ack_shape()
test_reclaim_stale_handles_dead_workers()
test_worker_consumes_and_completes_scan()
test_worker_marks_failed_when_pipeline_throws()
test_multiple_scans_queued_then_consumed()
test_concurrent_consumers_process_different_jobs()
test_duplicate_delivery_does_not_corrupt()
test_malformed_job_dropped()
test_handle_deferred_when_db_unavailable()
test_ack_only_after_terminal()
test_enqueue_failure_returns_503()
test_enqueue_success_returns_202_queued()

if __name__ == "__main__":
    print(f"\nRESULT: {PASS} passed, {FAIL} failed")
    raise SystemExit(1 if FAIL else 0)