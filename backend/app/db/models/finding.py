import uuid
from datetime import datetime

from sqlalchemy import DateTime, Enum, Float, ForeignKey, JSON, String, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.models.enums import Severity
from app.db.session import Base


def _values(e):
    return [x.value for x in e]


class Finding(Base):
    """Standardized finding emitted by any analyzer (§2.2)."""

    __tablename__ = "findings"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    scan_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("scans.id", ondelete="CASCADE"),
        index=True,
    )

    type: Mapped[str] = mapped_column(String(64))
    value: Mapped[str | None] = mapped_column(String(512), nullable=True)
    source: Mapped[str] = mapped_column(String(64))
    severity: Mapped[Severity] = mapped_column(
        Enum(Severity, name="severity_enum", values_callable=_values),
        default=Severity.INFO,
    )
    confidence: Mapped[float] = mapped_column(Float, default=1.0)
    evidence: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    location: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    tags: Mapped[list] = mapped_column(JSON, default=list)
    analyzer_version: Mapped[str] = mapped_column(String(64))
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )

    scan: Mapped["Scan"] = relationship(back_populates="findings")
