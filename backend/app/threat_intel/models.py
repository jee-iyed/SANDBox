"""Threat Intelligence enrichment - bounded result models.

Threat intelligence is an ENRICHMENT layer only (see DECISIONS.md D-17). It
runs AFTER the deterministic verdict/action/risk are persisted, never
participates in the decision, and stores ONLY bounded, normalized evidence in
the existing ``findings`` / ``analysis_results`` structure.

Design rules:
- bounded output: every field is capped; raw provider payloads are never stored
  and never exposed to the frontend,
- fail-safe: every lookup carries an explicit status
  (success/cached/unavailable/rate_limited/error/not_found/skipped);
  a failure is NEVER mapped to malicious/suspicious,
- secrets: API keys never appear in findings, logs or this response.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum

from pydantic import BaseModel, Field


class IndicatorType(str, Enum):
    """Supported indicator kinds (value is the finding/type key suffix)."""

    IP = "ip"
    URL = "url"
    DOMAIN = "domain"
    SHA256 = "sha256"


class LookupStatus(str, Enum):
    """Outcome of one provider lookup - never raises into the scan pipeline.

    ``success``   provider returned a parseable reputation answer,
    ``cached``    served from the shared TI cache (no provider call),
    ``not_found`` provider has no record for this indicator,
    ``unavailable`` provider unreachable / timeout / HTTP server error (5xx),
    ``rate_limited`` provider or our own limiter rejected the request (429),
    ``error``     malformed provider response or unexpected internal error,
    ``skipped``   not attempted (disabled, unsupported type, capacity cap).
    """

    SUCCESS = "success"
    CACHED = "cached"
    NOT_FOUND = "not_found"
    UNAVAILABLE = "unavailable"
    RATE_LIMITED = "rate_limited"
    ERROR = "error"
    SKIPPED = "skipped"


class TiLookup(BaseModel):
    """Bounded, sanitized result of one provider lookup for one indicator.

    This is the ONLY representation ever stored (JSON column) or exposed to the
    React client. It deliberately contains no raw provider JSON, no API keys,
    no internal limiter state and no Redis internals.
    """

    provider: str = Field(min_length=1, max_length=64)
    indicator_type: str = Field(min_length=1, max_length=16)
    indicator: str = Field(max_length=512)
    status: LookupStatus = LookupStatus.SKIPPED
    # Normalized reputation: provider-specific bounded number.
    #   AbuseIPDB -> abuse confidence score (0..100)
    #   VirusTotal -> % of detection engines that flagged the indicator (0..100)
    reputation: float | None = Field(default=None, ge=0.0, le=100.0)
    # Detection-engine counts (VirusTotal) / report counts (AbuseIPDB).
    malicious: int | None = Field(default=None, ge=0)
    suspicious: int | None = Field(default=None, ge=0)
    clean: int | None = Field(default=None, ge=0)
    undetected: int | None = Field(default=None, ge=0)
    total_engines: int | None = Field(default=None, ge=0)
    reports: int | None = Field(default=None, ge=0)
    distinct_users: int | None = Field(default=None, ge=0)
    # Human label: clean | suspicious | malicious | unknown | none.
    status_label: str = Field(default="unknown", max_length=16)
    confidence: float | None = Field(default=None, ge=0.0, le=1.0)
    first_seen: str | None = Field(default=None, max_length=64)
    last_seen: str | None = Field(default=None, max_length=64)
    categories: list[str] = Field(default_factory=list, max_length=20)
    provider_timestamp: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    cached: bool = False
    message: str | None = Field(default=None, max_length=300)
    retry_after_s: int | None = Field(default=None, ge=0, le=86400)

    def to_evidence(self) -> dict:
        """Bounded dict persisted as a Finding.evidence - minimal + stable."""
        evidence = {
            "provider": self.provider,
            "indicator_type": self.indicator_type,
            "indicator": self.indicator,
            "status": self.status.value,
            "status_label": self.status_label,
            "cached": self.cached,
            "provider_timestamp": self.provider_timestamp,
        }
        if self.reputation is not None:
            evidence["reputation"] = round(self.reputation, 1)
        if self.confidence is not None:
            evidence["confidence"] = round(self.confidence, 3)
        for key in (
            "malicious",
            "suspicious",
            "clean",
            "undetected",
            "total_engines",
            "reports",
            "distinct_users",
        ):
            value = getattr(self, key)
            if value is not None:
                evidence[key] = value
        if self.categories:
            evidence["categories"] = self.categories[:20]
        if self.first_seen:
            evidence["first_seen"] = self.first_seen
        if self.last_seen:
            evidence["last_seen"] = self.last_seen
        if self.message:
            evidence["message"] = self.message
        if self.retry_after_s is not None:
            evidence["retry_after_s"] = self.retry_after_s
        return evidence