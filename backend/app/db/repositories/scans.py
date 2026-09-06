import uuid
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.models import File, Scan, ScanStatus


def create(
    db: Session,
    *,
    filename: str,
    sha256: str,
    size_bytes: int,
    mime_type: str | None,
    detected_type: str | None,
    storage_path: str,
) -> Scan:
    scan = Scan()
    db.add(scan)
    db.flush()
    db.add(
        File(
            scan_id=scan.id,
            filename=filename,
            sha256=sha256,
            size_bytes=size_bytes,
            mime_type=mime_type,
            detected_type=detected_type,
            storage_path=storage_path,
        )
    )
    db.commit()
    return scan


def get(db: Session, scan_id: uuid.UUID) -> Scan | None:
    return db.get(Scan, scan_id)


def claim_next_queued(db: Session) -> Scan | None:
    stmt = (
        select(Scan)
        .where(Scan.status == ScanStatus.QUEUED)
        .order_by(Scan.created_at)
        .limit(1)
        .with_for_update(skip_locked=True)
    )
    return db.execute(stmt).scalar_one_or_none()


def mark_processing(db: Session, scan: Scan) -> None:
    scan.status = ScanStatus.PROCESSING
    db.commit()


def complete(
    db: Session,
    scan: Scan,
    *,
    verdict,
    action,
    risk_score: float,
) -> None:
    scan.status = ScanStatus.COMPLETED
    scan.verdict = verdict
    scan.action = action
    scan.risk_score = risk_score
    scan.completed_at = datetime.now(timezone.utc)
    db.commit()


def fail(db: Session, scan: Scan, message: str) -> None:
    scan.status = ScanStatus.FAILED
    scan.error_message = message[:2000]
    db.commit()
