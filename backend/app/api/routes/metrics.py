"""Minimal, non-sensitive worker and throughput observability."""
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends
from redis.exceptions import RedisError
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.core.config import settings
from app.db.models import Scan, ScanStatus
from app.db.session import get_db
from app.queue.client import get_redis
from app.queue.service import group_name, stream_name
from app.workers.processor import worker

router = APIRouter(prefix="/api/system", tags=["system"])


@router.get("/workers")
def workers_metrics(db: Session = Depends(get_db)):
    now = datetime.now(timezone.utc)
    window = now - timedelta(minutes=5)
    completed = db.query(func.count(Scan.id)).filter(Scan.status == ScanStatus.COMPLETED).scalar() or 0
    failed = db.query(func.count(Scan.id)).filter(Scan.status == ScanStatus.FAILED).scalar() or 0
    recent = db.query(Scan).filter(Scan.completed_at >= window, Scan.status == ScanStatus.COMPLETED).all()
    latencies = sorted((s.completed_at - s.created_at).total_seconds() * 1000 for s in recent if s.completed_at and s.created_at)
    p95 = latencies[min(len(latencies) - 1, int(len(latencies) * .95))] if latencies else None
    pending = None
    queue_depth = None
    try:
        redis = get_redis()
        pending = redis.xpending(stream_name(), group_name())["pending"]
        queue_depth = redis.xlen(stream_name())
    except (RedisError, KeyError, TypeError):
        pass
    snapshot = worker.snapshot()
    throughput = len(recent) * 12  # five-minute rolling completed scans -> per minute
    return {
        "configured_workers": settings.worker_max_threads,
        "active_workers": snapshot["active"], "idle_workers": max(0, settings.worker_max_threads - snapshot["active"]),
        "processing_workers": snapshot["active"], "completed_jobs": completed, "failed_jobs": failed,
        "queue_depth": queue_depth, "pending_jobs": pending,
        "throughput_files_per_minute": throughput, "target_files_per_minute": 350,
        "target_achieved": throughput >= 350, "average_latency_ms": round(sum(latencies) / len(latencies), 1) if latencies else None,
        "p95_latency_ms": round(p95, 1) if p95 is not None else None, "window_minutes": 5,
    }
