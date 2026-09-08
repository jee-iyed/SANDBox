import uuid
from datetime import datetime, timedelta, timezone

from sqlalchemy import and_, or_, select
from sqlalchemy.orm import Session

from app.db.models import (
    AnalysisResult,
    File,
    Finding,
    Report,
    Scan,
    ScanStatus,
)


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


def delete(db: Session, scan: Scan) -> None:
    """Best-effort removal of a just-created scan (queue enqueue rollback)."""
    db.delete(scan)
    db.commit()


def get(db: Session, scan_id: uuid.UUID) -> Scan | None:
    return db.get(Scan, scan_id)


def get_processable(
    db: Session, scan_id: uuid.UUID, *, lease_grace_s: float
) -> Scan | None:
    """Atomically claim ``scan_id`` for processing, or return ``None``.

    A scan may be processed when it is still QUEUED, or when it is PROCESSING
    but its lease has expired (``updated_at`` older than the visibility
    timeout - the previous worker crashed). Already-terminal scans can never
    be re-claimed, which makes duplicate job delivery safe and idempotent.
    """
    lease_cutoff = datetime.now(timezone.utc) - timedelta(seconds=lease_grace_s)
    row = (
        db.execute(
            select(Scan)
            .where(
                Scan.id == scan_id,
                or_(
                    Scan.status == ScanStatus.QUEUED,
                    and_(
                        Scan.status == ScanStatus.PROCESSING,
                        Scan.updated_at < lease_cutoff,
                    ),
                ),
            )
            .with_for_update()
        )
        .scalar_one_or_none()
    )
    return row


def mark_processing(db: Session, scan: Scan) -> None:
    scan.status = ScanStatus.PROCESSING
    db.commit()


def purge_partial_results(db: Session, scan: Scan) -> None:
    """Drop findings/results left by a crashed earlier attempt before re-running.

    Only meaningful when reclaiming a scan stuck in PROCESSING; harmless no-op
    for a fresh QUEUED scan (nothing was written yet).
    """
    if scan.status != ScanStatus.PROCESSING:
        return
    for model in (Finding, AnalysisResult, Report):
        db.query(model).filter(model.scan_id == scan.id).delete(
            synchronize_session=False
        )
    db.commit()


def stale_queued(db: Session) -> list[Scan]:
    """All scans waiting in QUEUED (startup rescue sweep).

    Re-enqueueing is idempotent: a duplicate job is later acknowledged as a
    no-op by the processing layer. This guarantees a QUEUED scan is never
    permanently stuck even if its job was lost between the DB insert and the
    Redis XADD.
    """
    stmt = (
        select(Scan)
        .where(Scan.status == ScanStatus.QUEUED)
        .order_by(Scan.created_at)
    )
    return list(db.execute(stmt).scalars())


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