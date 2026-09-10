import uuid
from datetime import datetime

from sqlalchemy import DateTime, Enum, ForeignKey, String, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.models.enums import SecureAccessStatus
from app.db.session import Base


def _vc(values):
    return [e.value for e in values]


class SecureFileAccess(Base):
    """Secure File Access request: a gateway-level wrapper over an existing scan.

    The scan owns the whole M1-M5 pipeline, findings, risk engine and verdict.
    This table ONLY records the access policy: source attribution, the
    temporary storage reference of the deliverable copy, the resolved access
    state and expiration. It never re-implements analysis logic.
    """

    __tablename__ = "secure_file_access"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    scan_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("scans.id", ondelete="CASCADE"),
        unique=True,
        index=True,
    )
    source_type: Mapped[str] = mapped_column(String(64), default="upload")
    source_identifier: Mapped[str | None] = mapped_column(String(512), nullable=True)
    original_filename: Mapped[str] = mapped_column(String(512))
    status: Mapped[SecureAccessStatus] = mapped_column(
        Enum(SecureAccessStatus, name="secure_access_status", values_callable=_vc),
        default=SecureAccessStatus.REQUESTED,
        index=True,
    )
    # Echo of the backend's deterministic action (allow/quarantine/sanitize/
    # reject) once the scan is complete. Stored as text to stay decoupled.
    policy_action: Mapped[str | None] = mapped_column(String(64), nullable=True)
    storage_reference: Mapped[str] = mapped_column(String(1024))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    scan: Mapped["Scan"] = relationship()  # noqa: F821  (resolved via strings)