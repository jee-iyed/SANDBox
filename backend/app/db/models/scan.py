import uuid
from datetime import datetime

from sqlalchemy import DateTime, Enum, Float, Text, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.models.enums import Action, ScanStatus, Verdict
from app.db.session import Base


def _vc(values):
    return [e.value for e in values]


class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    status: Mapped[ScanStatus] = mapped_column(
        Enum(ScanStatus, name="scan_status", values_callable=_vc),
        default=ScanStatus.QUEUED,
        index=True,
    )
    verdict: Mapped[Verdict] = mapped_column(
        Enum(Verdict, name="verdict", values_callable=_vc),
        default=Verdict.NOT_ANALYZED,
    )
    action: Mapped[Action | None] = mapped_column(
        Enum(Action, name="action_enum", values_callable=_vc), nullable=True
    )
    risk_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )
    completed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    file: Mapped["File"] = relationship(
        back_populates="scan", uselist=False, cascade="all, delete-orphan"
    )
    findings: Mapped[list["Finding"]] = relationship(
        back_populates="scan", cascade="all, delete-orphan"
    )
    analysis_results: Mapped[list["AnalysisResult"]] = relationship(
        back_populates="scan", cascade="all, delete-orphan"
    )
    reports: Mapped[list["Report"]] = relationship(
        back_populates="scan", cascade="all, delete-orphan"
    )
