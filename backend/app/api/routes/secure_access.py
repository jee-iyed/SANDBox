"""Secure File Access API (gateway workflow).

Exposes the secure-access lifecycle described in DECISIONS.md D-16:

  POST /api/secure-access                - create a secure access request
                                            (MODE 1: multipart file upload;
                                             MODE 2: external reference JSON)
  GET  /api/secure-access/{access_id}    - current access state + decision
  GET  /api/secure-access/{access_id}/content
                                         - authorized content ONLY (fail-closed)

Security contract:
* The file is stored only under sandbox_storage/ (never web-exposed); the
  upload copy used by the M1-M5 pipeline lives under uploads/ like any scan.
* The original file is NEVER downloadable from these endpoints.
* /content answers 403 until the scan completed with an allowable verdict and
  the access is unexpired; unknown/error/timeout => DENY.
* Filenames are sanitized metadata; storage paths use generated UUIDs only.

AUTHENTICATION: PROTOTYPE. This endpoint is NOT production-safe unauthnticated;
production deployments MUST authenticate the client platform (integration
token/credential) before exposing it.
"""

from __future__ import annotations

import hashlib
import logging
import uuid as uuidlib
from typing import Annotated

from fastapi import APIRouter, Body, Depends, File, Form, Header, HTTPException, UploadFile
from redis.exceptions import RedisError
from sqlalchemy.orm import Session

from app.api.schemas import (
    ExternalSourcePayload,
    SecureAccessRead,
    SecureContentRead,
)
from app.db import repositories
from app.db.models import Scan, SecureAccessStatus
from app.db.session import get_db
from app.queue.service import enqueue_scan
from app.secure_access import (
    create_access,
    deny_reason,
    parse_source,
    raise_if_oversized,
    refresh,
    secure_content_service,
)
from app.secure_access.client_sources import UPLOAD_SOURCE
from app.storage.manager import storage

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/secure-access", tags=["secure-access"])

X_SOURCE_TOKEN = "x-source-token"


def _read_model(access, scan) -> SecureAccessRead:
    preview = access.status == SecureAccessStatus.AUTHORIZED
    return SecureAccessRead(
        id=access.id,
        scan_id=access.scan_id,
        source_type=access.source_type,
        source_identifier=access.source_identifier,
        original_filename=access.original_filename,
        status=access.status,
        policy_action=access.policy_action,
        verdict=scan.verdict if scan else None,
        risk_score=scan.risk_score if scan else None,
        preview_available=preview,
        expires_at=access.expires_at,
        created_at=access.created_at,
        updated_at=access.updated_at,
    )


def _load_access(db: Session, access_id: uuidlib.UUID):
    from app.db.models import SecureFileAccess

    return db.get(SecureFileAccess, access_id)


@router.post("", response_model=SecureAccessRead, status_code=202)
async def create_secure_access(
    file: Annotated[UploadFile | None, File(description="MODE 1: file bytes")] = None,
    source_identifier: Annotated[str | None, Form()] = None,
    external: Annotated[ExternalSourcePayload | None, Body()] = None,
    x_source_token: Annotated[str | None, Header(alias=X_SOURCE_TOKEN)] = None,
    db: Session = Depends(get_db),
):
    """Create a secure file access request and enqueue the scan (existing queue)."""
    if file is not None:
        if external is not None:
            raise HTTPException(status_code=422, detail="Use either a file upload or a JSON reference, not both")
        try:
            source = parse_source(
                source_type=UPLOAD_SOURCE,
                source_identifier=source_identifier or x_source_token,
            )
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        data = await file.read()
        if not data:
            raise HTTPException(status_code=400, detail="Empty file")
        try:
            raise_if_oversized(len(data))
        except ValueError as exc:
            raise HTTPException(status_code=413, detail=str(exc)) from exc
        filename = file.filename or "unnamed"
    else:
        # MODE 2 - external secure reference. Retrieval is NOT implemented:
        # we explicitly refuse rather than guess a filesystem path/URL.
        raise HTTPException(
            status_code=501,
            detail=(
                "External reference retrieval is not configured. "
                "Use MODE 1 (multipart file upload) or complete a real client-platform "
                "integration (see DECISIONS.md D-16)."
            ),
        )

    sha256 = hashlib.sha256(data).hexdigest()
    storage.save_upload(sha256, data)

    scan = repositories.create(
        db,
        filename=filename,
        sha256=sha256,
        size_bytes=len(data),
        mime_type=file.content_type if file else None,
        detected_type=None,
        storage_path=f"uploads/{sha256}.bin",
    )

    access_id = uuidlib.uuid4()
    try:
        access = create_access(
            db,
            scan=scan,
            access_id=access_id,
            filename=filename,
            source_type=source.source_type,
            source_identifier=source.source_identifier,
            data=data,
        )
    except Exception:
        logger.exception("SA_CREATE storage_failed access_id=%s scan_id=%s", access_id, scan.id)
        try:
            repositories.delete(db, scan)
        except Exception:  # noqa: BLE001 - best-effort rollback
            db.rollback()
        raise HTTPException(status_code=500, detail="Unable to stage secure file")

    try:
        enqueue_scan(scan.id)
    except RedisError as exc:
        logger.exception("QUEUE_ERROR enqueue_failed scan_id=%s", scan.id)
        try:
            repositories.delete(db, scan)
        except Exception:  # noqa: BLE001 - best-effort rollback
            db.rollback()
        raise HTTPException(status_code=503, detail="Scan queue unavailable") from exc

    return _read_model(access, scan)


@router.get("/{access_id}", response_model=SecureAccessRead)
def get_secure_access(access_id: uuidlib.UUID, db: Session = Depends(get_db)):
    access = _load_access(db, access_id)
    if access is None:
        raise HTTPException(status_code=404, detail="Secure access request not found")
    refresh(db, access)
    scan = db.get(Scan, access.scan_id)
    return _read_model(access, scan)


@router.get("/{access_id}/content", response_model=SecureContentRead)
def get_secure_access_content(access_id: uuidlib.UUID, db: Session = Depends(get_db)):
    """Return authorized content ONLY (currently a controlled placeholder)."""
    access = _load_access(db, access_id)
    if access is None:
        raise HTTPException(status_code=404, detail="Secure access request not found")
    refresh(db, access)
    if access.status != SecureAccessStatus.AUTHORIZED:
        raise HTTPException(
            status_code=403,
            detail=deny_reason(access.status),
        )
    delivery = secure_content_service.delivery_response(access.status)
    return SecureContentRead(
        authorized=True,
        content_kind=delivery["content_kind"],
        message=delivery["message"],
        filename=access.original_filename,
        mime_type=delivery["mime_type"],
        size_bytes=delivery["size_bytes"],
        deny_reason="The original file is never served. Rendering inside the sandbox is "
        "not implemented yet - a placeholder is returned instead.",
    )