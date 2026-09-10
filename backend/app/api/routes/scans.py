import hashlib
import logging
import uuid as uuidlib

from fastapi import APIRouter, Depends, HTTPException, UploadFile
from redis.exceptions import RedisError
from sqlalchemy.orm import Session, selectinload

from app.api.schemas import ScanDetail, ScanRead
from app.core.config import settings
from app.db import repositories
from app.db.models import Scan
from app.db.session import get_db
from app.queue.service import enqueue_scan
from app.storage.manager import storage

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/scans", tags=["scans"])

_LOAD_OPTS = (
    selectinload(Scan.file),
    selectinload(Scan.findings),
    selectinload(Scan.analysis_results),
)


def _load(db: Session, scan_id: uuidlib.UUID) -> Scan | None:
    return (
        db.query(Scan)
        .options(*_LOAD_OPTS)
        .filter(Scan.id == scan_id)
        .first()
    )


@router.post("", response_model=ScanRead, status_code=202)
def create_scan(file: UploadFile, db: Session = Depends(get_db)):
    data = file.file.read()
    max_bytes = settings.max_upload_mb * 1024 * 1024
    if not data:
        raise HTTPException(status_code=400, detail="Empty file")
    if len(data) > max_bytes:
        raise HTTPException(
            status_code=413, detail=f"File too large (max {settings.max_upload_mb}MB)"
        )

    sha256 = hashlib.sha256(data).hexdigest()
    storage.save_upload(sha256, data)

    scan = repositories.create(
        db,
        filename=file.filename or "unnamed",
        sha256=sha256,
        size_bytes=len(data),
        mime_type=file.content_type,
        detected_type=None,
        storage_path=f"uploads/{sha256}.bin",
    )
    try:
        enqueue_scan(scan.id)
    except RedisError as exc:
        logger.exception("QUEUE_ERROR enqueue_failed scan_id=%s", scan.id)
        try:
            repositories.delete(db, scan)
        except Exception:  # noqa: BLE001 - best-effort rollback
            db.rollback()
        raise HTTPException(status_code=503, detail="Scan queue unavailable") from exc
    return _load(db, scan.id)


@router.get("", response_model=list[ScanRead])
def list_scans(limit: int = 50, offset: int = 0, db: Session = Depends(get_db)):
    rows = (
        db.query(Scan)
        .options(selectinload(Scan.file))
        .order_by(Scan.created_at.desc())
        .offset(offset)
        .limit(min(limit, 200))
        .all()
    )
    return rows


@router.get("/{scan_id}", response_model=ScanDetail)
def get_scan(scan_id: uuidlib.UUID, db: Session = Depends(get_db)):
    scan = _load(db, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan
