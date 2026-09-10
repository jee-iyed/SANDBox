"""Secure File Access orchestration (observes the scan, never re-implements it).

The SecureFileAccess record wraps a normal Scan. The worker / M1-M5 pipeline /
risk engine are untouched: this service only derives the access state from the
scan's current state (state machine in ``states.py``), moves the temporary
deliverable copy accordingly, enforces the TTL and answers fail-closed.
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.db.models import Scan, SecureAccessStatus, SecureFileAccess
from app.secure_access.client_sources import sanitize_filename
from app.secure_access.storage import secure_storage
from app.secure_access.states import resolve_status

logger = logging.getLogger(__name__)


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def expires_from_now() -> datetime:
    return utcnow() + timedelta(minutes=settings.secure_access_ttl_minutes)


def raise_if_oversized(size_bytes: int) -> None:
    """Enforce the configured upload bound (shared by endpoint + tests)."""
    max_bytes = settings.max_upload_mb * 1024 * 1024
    if size_bytes > max_bytes:
        raise ValueError(f"File too large (max {settings.max_upload_mb}MB)")


def create_access(
    db: Session,
    *,
    scan,
    access_id: uuid.UUID,
    filename: str | None,
    source_type: str,
    source_identifier: str | None,
    data: bytes,
) -> SecureFileAccess:
    """Persist a SecureFileAccess row recorded against an already-created scan.

    The original file bytes are dangerous-free metadata here: the deliverable
    copy is stored under ``sandbox_storage/pending/<access_id>.bin`` (generated
    id, never the filename). Caller is responsible for enqueuing the scan.
    """
    original_filename = sanitize_filename(filename)
    ref = secure_storage.write_pending(access_id, data)
    access = SecureFileAccess(
        id=access_id,
        scan_id=scan.id,
        source_type=source_type,
        source_identifier=source_identifier,
        original_filename=original_filename,
        status=SecureAccessStatus.REQUESTED,
        policy_action=None,
        storage_reference=ref,
        expires_at=expires_from_now(),
    )
    db.add(access)
    db.commit()
    return access


def refresh(db: Session, access: SecureFileAccess, now: datetime | None = None) -> SecureFileAccess:
    """Reconcile the access state against its scan (+ expiry) and persist it.

    Idempotent and safe to call on every read: transitions only happen when the
    resolved state differs from the stored one.
    """
    now = now or utcnow()
    scan = db.get(Scan, access.scan_id)
    if scan is None:
        status, policy_action = SecureAccessStatus.FAILED, None
    else:
        status, policy_action = resolve_status(
            scan_status=scan.status.value if hasattr(scan.status, "value") else str(scan.status),
            verdict=scan.verdict.value if hasattr(scan.verdict, "value") else str(scan.verdict),
            action=scan.action.value if scan.action else None,
            expires_at=access.expires_at,
            now=now,
        )
    if access.status != status or access.policy_action != policy_action:
        new_ref = secure_storage.apply_transition(
            access.id, access.storage_reference, status.value
        )
        access.status = status
        access.policy_action = policy_action
        access.storage_reference = new_ref
        db.commit()
        logger.info("SA_STATE access=%s scan=%s status=%s", access.id, access.scan_id, status.value)
    return access


def cleanup_expired(db: Session, now: datetime | None = None) -> int:
    """Best-effort maintenance: expires + cleans every stale access.

    Called at startup; cheap for dev-scale data. Fail-closed: reconciles each
    row through the same path used by GET.
    """
    rows = list(db.execute(select(SecureFileAccess)).scalars())
    refreshed = 0
    for access in rows:
        refresh(db, access, now=now)
        refreshed += 1
    return refreshed


_DENY = {
    SecureAccessStatus.SCANNING: "Access denied: analysis still in progress.",
    SecureAccessStatus.BLOCKED: "Access denied: the file was blocked by the security decision.",
    SecureAccessStatus.QUARANTINED: "Access denied: the file was quarantined and is isolated.",
    SecureAccessStatus.FAILED: "Access denied: the analysis failed. Verify and retry.",
    SecureAccessStatus.EXPIRED: "Access denied: the secure access request has expired.",
    SecureAccessStatus.REQUESTED: "Access denied: the request is still being created.",
}


def deny_reason(status: SecureAccessStatus) -> str:
    return _DENY.get(status, "Access denied: the file is not authorized.")