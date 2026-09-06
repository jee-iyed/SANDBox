from dataclasses import dataclass, field

from sqlalchemy.orm import Session

from app.db.models import Finding, Severity


@dataclass
class FindingSpec:
    """Normalized finding payload produced by every analyzer (§2.2)."""

    type: str
    source: str
    analyzer_version: str
    severity: Severity = Severity.INFO
    confidence: float = 1.0
    value: str | None = None
    evidence: dict | None = None
    location: dict | None = None
    tags: list[str] = field(default_factory=list)


def to_model(spec: FindingSpec, scan_id) -> Finding:
    return Finding(
        scan_id=scan_id,
        type=spec.type,
        value=spec.value,
        source=spec.source,
        severity=spec.severity,
        confidence=max(0.0, min(1.0, spec.confidence)),
        evidence=spec.evidence,
        location=spec.location,
        tags=spec.tags,
        analyzer_version=spec.analyzer_version,
    )
