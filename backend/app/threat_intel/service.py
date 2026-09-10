"""Threat Intelligence enrichment service.

Runs AFTER the deterministic verdict/action/risk are persisted and NEVER
modifies them (see DECISIONS.md D-17). API:

- ``TiService.enrich_scan(db, scan)`` extracts indicators (file SHA-256, QR
  URLs, network findings), performs cached + rate-limited provider lookups, and
  persists bounded TI evidence in the EXISTING findings/analysis_results tables
  (no schema change).

Hard guarantees:

- TI disabled -> zero behavior change, zero DB traffic, zero provider calls,
- every provider failure maps to a bounded status; scans never fail because of
  TI (the worker hook catches everything),
- no file bytes are ever sent externally (SHA-256 lookups only), no auto
  submission of URLs, no REPORT calls, no SSRF (only normalized indicators
  already present in the local analysis are queried),
- API keys are never logged and never persisted.
"""

from __future__ import annotations

import logging
import time

from app.threat_intel.cache import TiCache
from app.threat_intel.extraction import extract_indicators
from app.threat_intel.models import LookupStatus, TiLookup
from app.threat_intel.rate_limit import RateLimiter, default_limiter
from app.threat_intel.providers import build_providers

logger = logging.getLogger(__name__)

_VERSION = "0.1.0"
_MAX_FINDINGS_SCAN = 400


def _confidence_for(lookup: TiLookup) -> float:
    if lookup.confidence is not None:
        return max(0.0, min(1.0, lookup.confidence))
    if lookup.status in (LookupStatus.SUCCESS, LookupStatus.CACHED):
        return 1.0
    return 0.0


class TiService:
    def __init__(
        self,
        *,
        providers: list | None = None,
        cache: TiCache | None = None,
        limiter: RateLimiter | None = None,
        http=None,
    ) -> None:
        # NOTE: providers/cache/limiter are injected for tests. The defaults
        # resolve lazily so the env can be changed between instantiations.
        self._providers_override = providers
        self._cache = cache
        self._limiter = limiter if limiter is not None else default_limiter()
        self._http = http

    @property
    def enabled(self) -> bool:
        from app.core.config import settings

        if not settings.ti_enabled:
            return False
        if self._providers_override is not None:
            return len(self._providers_override) > 0
        return bool(build_providers(limiter=self._limiter, http=self._http))

    def providers(self) -> list:
        from app.core.config import settings

        if self._providers_override is not None:
            return list(self._providers_override)
        if not settings.ti_enabled:
            return []
        return build_providers(limiter=self._limiter, http=self._http)

    def enrich_scan(self, db, scan) -> dict | None:
        """Enrich one scan with bounded TI evidence. Returns a summary or None.

        ``db`` is a SQLAlchemy Session (only ``query``/``add``/``commit`` are
        used). Never raises; on unexpected errors returns an error summary and
        leaves the deterministic scan state untouched.
        """
        from app.core.config import settings

        started = time.perf_counter()
        enabled = self.enabled
        if not enabled:
            return None
        if scan is None or getattr(scan, "id", None) is None:
            return self._summary(enabled, [], started, error="scan unavailable")

        providers = self.providers()
        if not providers:
            return self._summary(enabled, [], started, note="no_providers_configured")

        try:
            indicators = self._collect_indicators(db, scan)
        except Exception as exc:  # noqa: BLE001 - TI never kills a scan
            logger.exception("TI_ERROR scan_id=%s", getattr(scan, "id", None))
            return self._summary(enabled, providers, started, error=f"{exc}")

        cache = self._cache if self._cache is not None else TiCache(ttl_s=settings.ti_cache_ttl_seconds)
        cache_ttl = settings.ti_cache_ttl_seconds
        lookups: list[TiLookup] = []

        for provider in providers:
            for indicator in indicators:
                if not provider.supports_type(indicator.type):
                    continue
                try:
                    lookup = self._single_lookup(provider, indicator, cache, cache_ttl)
                except Exception as exc:  # noqa: BLE001 - per-lookup fail-safe
                    lookup = TiLookup(
                        provider=provider.name,
                        indicator_type=indicator.type,
                        indicator=indicator.value,
                        status=LookupStatus.ERROR,
                        message=f"internal_error ({exc.__class__.__name__})",
                    )
                lookups.append(lookup)

        return self._persist(db, scan, enabled, providers, indicators, lookups, started)

    # -- internals ---------------------------------------------------------

    def _collect_indicators(self, db, scan) -> list:
        """Load QR payload + findings once, then normalize/dedupe."""
        from app.core.config import settings

        file_sha256 = None
        file_obj = getattr(scan, "file", None)
        if file_obj is not None:
            file_sha256 = getattr(file_obj, "sha256", None)

        analysis_results: list = []
        findings: list = []
        try:
            from app.db.models import AnalysisResult, Finding

            if db is not None:
                analysis_results = (
                    db.query(AnalysisResult)
                    .filter(AnalysisResult.scan_id == scan.id, AnalysisResult.analyzer == "qr_analysis")
                    .limit(5)
                    .all()
                )
                findings = (
                    db.query(Finding)
                    .filter(Finding.scan_id == scan.id)
                    .limit(_MAX_FINDINGS_SCAN)
                    .all()
                )
        except Exception as exc:  # noqa: BLE001 - never fail the scan over extraction
            logger.warning("TI extract db error scan_id=%s err=%s", getattr(scan, "id", None), exc)

        return extract_indicators(
            file_sha256=file_sha256,
            analysis_results=analysis_results,
            findings=findings,
            max_indicators=settings.ti_max_indicators_per_scan,
        )

    def _single_lookup(self, provider, indicator, cache: TiCache, ttl: int) -> TiLookup:
        cached = cache.get(provider.name, indicator.type, indicator.value)
        if cached is not None:
            cached.status = LookupStatus.CACHED
            cached.cached = True
            return cached
        lookup = provider.lookup(indicator)
        if lookup.status in (LookupStatus.SUCCESS, LookupStatus.NOT_FOUND):
            cache.set(lookup, ttl_s=ttl)
        return lookup

    def _persist(self, db, scan, enabled, providers, indicators, lookups, started) -> dict:
        from app.core.config import settings

        from app.db.models import AnalysisResult, AnalysisStatus, Severity
        from app.findings.schema import FindingSpec, to_model

        try:
            version = settings.ANALYZER_VERSIONS.get("threat_intel", _VERSION)
            for lookup in lookups:
                db.add(
                    to_model(
                        FindingSpec(
                            type=f"ti_{lookup.provider}_{lookup.indicator_type}",
                            source="threat_intel",
                            analyzer_version=version,
                            severity=Severity.INFO,
                            confidence=_confidence_for(lookup),
                            value=lookup.indicator,
                            evidence=lookup.to_evidence(),
                            tags=["threat_intel", lookup.provider, lookup.status.value],
                        ),
                        scan.id,
                    )
                )
            db.add(
                AnalysisResult(
                    scan_id=scan.id,
                    analyzer="threat_intel",
                    analyzer_version=version,
                    status=AnalysisStatus.OK,
                    duration_ms=int((time.perf_counter() - started) * 1000),
                    payload=self._summary_payload(providers, indicators, lookups),
                )
            )
            db.commit()
        except Exception as exc:  # noqa: BLE001 - never kill the scan on persist error
            logger.exception("TI_PERSIST error scan_id=%s", getattr(scan, "id", None))
            try:
                db.rollback()
            except Exception:  # noqa: BLE001
                pass
            return self._summary(enabled, providers, started, error=f"persist_error {exc}")

        summary = self._summary(enabled, providers, started)
        logger.info(
            "TI_RESULT scan_id=%s providers=%s lookups=%s duration_ms=%s",
            getattr(scan, "id", None),
            ",".join(p.name for p in providers),
            len(lookups),
            summary["duration_ms"],
        )
        return summary

    def _summary_payload(self, providers, indicators, lookups) -> dict:
        providers_payload: dict = {}
        for provider in providers:
            per_provider = {
                "lookups": 0,
                "success": 0,
                "cached": 0,
                "not_found": 0,
                "unavailable": 0,
                "rate_limited": 0,
                "error": 0,
                "skipped": 0,
            }
            for lookup in lookups:
                if lookup.provider != provider.name:
                    continue
                per_provider["lookups"] += 1
                status = lookup.status.value
                if status in per_provider:
                    per_provider[status] += 1
                if lookup.cached:
                    per_provider["cached"] += 1
            providers_payload[provider.name] = per_provider
        return {
            "enabled": True,
            "status": "ok",
            "indicators_extracted": len(indicators),
            "lookups": len(lookups),
            "providers": providers_payload,
            "analyzer_version": _VERSION,
        }

    def _summary(self, enabled: bool, providers, started, *, error: str | None = None, note: str | None = None) -> dict:
        return {
            "enabled": bool(enabled),
            "status": "error" if error else ("ok" if providers else (note or "disabled")),
            "providers": [p.name for p in providers],
            "error": (str(error)[:300] if error else None),
            "duration_ms": int((time.perf_counter() - started) * 1000),
        }


def run_threat_intel(db, scan) -> dict | None:
    """Worker hook: bounded post-decision enrichment. Never raises."""
    try:
        return TiService().enrich_scan(db, scan)
    except Exception as exc:  # noqa: BLE001 - TI must never fail a scan
        logger.exception("TI_UNEXPECTED scan_id=%s", getattr(scan, "id", None))
        return {"enabled": True, "status": "error", "error": str(exc)[:300], "providers": []}