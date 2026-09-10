import uuid
from datetime import datetime
from typing import Optional

from pydantic import BaseModel, ConfigDict

from app.db.models import (
    Action,
    ScanStatus,
    SecureAccessStatus,
    Severity,
    Verdict,
)


class FileRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    filename: str
    sha256: str
    size_bytes: int
    mime_type: Optional[str] = None
    detected_type: Optional[str] = None
    quarantined: bool = False


class FindingRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    type: str
    value: Optional[str] = None
    source: str
    severity: Severity
    confidence: float
    evidence: Optional[dict] = None
    location: Optional[dict] = None
    tags: list = []
    analyzer_version: str
    timestamp: datetime


class ScanRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    status: ScanStatus
    verdict: Verdict
    action: Optional[Action] = None
    risk_score: Optional[float] = None
    created_at: datetime
    updated_at: datetime
    completed_at: Optional[datetime] = None
    file: Optional[FileRead] = None


class AnalysisResultRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    analyzer: str
    analyzer_version: str
    status: str
    duration_ms: Optional[int] = None
    payload: Optional[dict] = None
    error: Optional[str] = None
    created_at: datetime


class ScanDetail(ScanRead):
    findings: list[FindingRead] = []
    analysis_results: list[AnalysisResultRead] = []


class ExternalSourcePayload(BaseModel):
    """MODE 2 - secure file reference (no bytes in this request).

    ``external_reference`` retrieval is NOT implemented yet: the endpoint
    answers 501 until a real, authenticated client-platform integration
    exists. SANDBox never blindly fetches URLs.
    """

    source_type: str = "external_reference"
    source_token: str
    filename: str = "unnamed"
    source_identifier: Optional[str] = None


class SecureAccessRead(BaseModel):
    id: uuid.UUID
    scan_id: uuid.UUID
    source_type: str
    source_identifier: Optional[str] = None
    original_filename: str
    status: SecureAccessStatus
    policy_action: Optional[Action] = None
    verdict: Optional[Verdict] = None
    risk_score: Optional[float] = None
    preview_available: bool = False
    expires_at: datetime
    created_at: datetime
    updated_at: datetime


class SecureContentRead(BaseModel):
    """Secure-content endpoint response (never the original bytes today)."""

    authorized: bool
    content_kind: str
    message: str
    deny_reason: Optional[str] = None
    filename: Optional[str] = None
    mime_type: Optional[str] = None
    size_bytes: Optional[int] = None
