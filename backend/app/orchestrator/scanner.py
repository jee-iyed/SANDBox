from sqlalchemy.orm import Session

from app.core.config import settings
from app.db import repositories
from app.db.models import Action, AnalysisStatus, AnalysisResult, Scan, Severity, Verdict
from app.findings.schema import FindingSpec, to_model

from app.analyzers.fast_scan.analyzer import FastScanAnalyzer
from app.analyzers.dynamic.analyzer import DynamicAnalyzer
from app.analyzers.static.analyzer import StaticAnalyzer
from app.analyzers.static.structural import StructuralAnalyzer
from app.analyzers.yara.analyzer import YaraAnalyzer


def _analyzers() -> list:
    return [
        FastScanAnalyzer(),
        StaticAnalyzer(),
        StructuralAnalyzer(),
        YaraAnalyzer(),
        DynamicAnalyzer(),
    ]


def _weight(sev: Severity) -> float:
    return {
        Severity.INFO: 0.0,
        Severity.LOW: 10.0,
        Severity.MEDIUM: 30.0,
        Severity.HIGH: 70.0,
        Severity.CRITICAL: 100.0,
    }.get(sev, 0.0)


def _decide(risk: float):
    """PROVISIONAL decision mapping - thresholds UNCONFIRMED by client (§8).

    Kept separate from the analytical 'risk score' (§2.4): risk is quantitative,
    verdict+action are policy decisions derived from it.
    """
    if risk <= settings.risk_safe_max:
        return Verdict.SAFE, Action.ALLOW
    if risk < settings.risk_malicious_min:
        return Verdict.SUSPICIOUS, Action.QUARANTINE
    return Verdict.MALICIOUS, Action.REJECT


def run_pipeline(db: Session, scan: Scan) -> None:
    import time as _t

    total_risk = 0.0
    for analyzer in _analyzers():
        started = _t.perf_counter()
        specs: list[FindingSpec] = []
        status = AnalysisStatus.OK
        error = None
        payload = None
        try:
            specs = list(analyzer.analyze(db, scan))
            get_payload = getattr(analyzer, "get_payload", None)
            payload = get_payload() if get_payload else None
        except Exception as exc:  # analyzer must never crash the whole scan job
            status = AnalysisStatus.ERROR
            error = str(exc)[:300]
        for spec in specs:
            db.add(to_model(spec, scan.id))
            total_risk += _weight(spec.severity) * spec.confidence
        db.add(
            AnalysisResult(
                scan_id=scan.id,
                analyzer=analyzer.name,
                analyzer_version=analyzer.version,
                status=status,
                duration_ms=int((_t.perf_counter() - started) * 1000),
                payload=payload,
                error=error,
            )
        )
    db.commit()

    verdict, action = _decide(total_risk)
    repositories.complete(db, scan, verdict=verdict, action=action, risk_score=total_risk)
