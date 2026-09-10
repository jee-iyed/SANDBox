"""Threat Intelligence - indicator extraction (deduplicated, bounded).

Collects the indicators SANDBox already observed during M1-M5/QR analysis:

- the scanned file's SHA-256 (VirusTotal SHA-256 reputation lookup; the file
  itself is never uploaded),
- QR-decoded URLs (from the ``qr_analysis`` AnalysisResult payload),
- network indicators contained in existing findings (dns / network events,
  suspicious URLs, IP literals, ...) and selected evidence fields.

Indicators are normalized, deduplicated per scan and capped so a noisy file can
never trigger an unbounded number of external lookups.

Important privacy property: only hashes/hostnames/IPs already present in the
local analysis are forwarded - never file bytes, never free text.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable

from app.threat_intel.normalization import (
    _SHA256_RE,
    is_public_ip,
    normalize_domain,
    normalize_ip,
    normalize_url,
)

# Finding types that may carry network indicators worth enriching.
_NETWORK_FINDING_TYPES = re.compile(
    r"(dns|dns_request|http|https|network|url|domain|ip|host|socket|mail|connection)"
    r"|(static_suspicious_url|static_ipv4_literal)",
    re.IGNORECASE,
)

# Evidence keys that are allowed to carry an indicator (bounded allow-list).
_EVIDENCE_KEYS = ("url", "uri", "domain", "host", "ip", "ip_address", "ipAddr",
                  "sha256", "hash", "indicator", "destination", "dst")


@dataclass(frozen=True)
class TiIndicator:
    """One deduplicated, normalized indicator for a scan."""

    type: str  # IndicatorType value: ip | url | domain | sha256
    value: str

    @property
    def key(self) -> tuple[str, str]:
        return (self.type, self.value)


def _scan_urls_in_text(text: str, out: list[TiIndicator], seen: set) -> None:
    for match in re.findall(r"\bhttps?://[^\s<>\"']+", text or ""):
        norm = normalize_url(match)
        if norm is None:
            continue
        item = ("url", norm)
        if item not in seen:
            seen.add(item)
            out.append(TiIndicator("url", norm))


def _indicator_from_value(value) -> TiIndicator | None:
    if not isinstance(value, str) or not value or len(value) > 512:
        return None
    stripped = value.strip()
    if not stripped or any(c.isspace() for c in stripped):
        return None
    if normalize_ip(stripped) is not None:
        return TiIndicator("ip", normalize_ip(stripped))
    norm_url = normalize_url(stripped)
    if norm_url is not None:
        return TiIndicator("url", norm_url)
    norm_domain = normalize_domain(stripped.rstrip("."))
    if norm_domain is not None:
        return TiIndicator("domain", norm_domain)
    if _SHA256_RE.match(stripped):
        return TiIndicator("sha256", stripped.lower())
    return None


def _extract_from_finding(finding, out: list[TiIndicator], seen: set) -> None:
    ftype = getattr(finding, "type", "") or ""
    value = getattr(finding, "value", None)
    evidence = getattr(finding, "evidence", None)

    networkish = isinstance(ftype, str) and bool(_NETWORK_FINDING_TYPES.search(ftype))
    if networkish and isinstance(value, str):
        if value and ":" in value and not value.startswith(("http://", "https://")):
            # sandbox network_attempt -> "destination:port"
            candidate = value.rsplit(":", 1)[0]
            if candidate:
                item = _indicator_from_value(candidate)
                if item and item.key not in seen:
                    seen.add(item.key)
                    out.append(item)
        elif value:
            item = _indicator_from_value(value.rstrip("."))
            if item and item.key not in seen:
                seen.add(item.key)
                out.append(item)

    if isinstance(evidence, dict):
        for key, item in evidence.items():
            if key not in _EVIDENCE_KEYS:
                continue
            if isinstance(item, str) and item:
                # network_attempt evidence stores destination separately too.
                if ":" in item and not item.startswith(("http://", "https://")):
                    candidate = item.rsplit(":", 1)[0]
                    if candidate:
                        found = _indicator_from_value(candidate)
                        if found and found.key not in seen:
                            seen.add(found.key)
                            out.append(found)
                found = _indicator_from_value(item.rstrip("."))
                if found and found.key not in seen:
                    seen.add(found.key)
                    out.append(found)
            elif isinstance(item, (list, tuple)):
                for sub in item[:10]:
                    if isinstance(sub, str) and sub:
                        found = _indicator_from_value(sub.rstrip("."))
                        if found and found.key not in seen:
                            seen.add(found.key)
                            out.append(found)


def _extract_from_payload(payload: dict | None, out: list[TiIndicator], seen: set) -> None:
    if not isinstance(payload, dict):
        return
    urls = payload.get("urls")
    if isinstance(urls, list):
        for url in urls[: settings_qr_codes()]:
            if not isinstance(url, str):
                continue
            norm = normalize_url(url)
            if norm is None:
                continue
            item = ("url", norm)
            if item not in seen:
                seen.add(item)
                out.append(TiIndicator("url", norm))
    payloads = payload.get("payloads")
    if isinstance(payloads, list):
        for blob in payloads[: settings_qr_codes()]:
            if isinstance(blob, str):
                _scan_urls_in_text(blob, out, seen)


def settings_qr_codes() -> int:
    from app.core.config import settings  # local import to avoid cycle

    return int(getattr(settings, "qr_max_codes", 20) or 20)


def extract_indicators(
    *,
    file_sha256: str | None,
    analysis_results: Iterable | None = None,
    findings: Iterable | None = None,
    max_indicators: int | None = None,
    include_file_hash: bool = True,
) -> list[TiIndicator]:
    """Extract + normalize + dedupe indicators for one scan (no DB required).

    ``analysis_results`` / ``findings`` may be ORM collections or plain
    objects exposing ``analyzer`` / ``payload`` and ``type`` / ``value`` /
    ``evidence`` respectively. Callers load them from the DB once.
    """
    from app.core.config import settings  # local import to avoid a hard cycle

    limit = max_indicators if max_indicators is not None else settings.ti_max_indicators_per_scan
    out: list[TiIndicator] = []
    seen: set[tuple[str, str]] = set()

    def _add(ind: TiIndicator) -> None:
        if ind.key in seen or len(out) >= limit:
            return
        seen.add(ind.key)
        out.append(ind)

    if include_file_hash and isinstance(file_sha256, str):
        norm = file_sha256.strip().lower()
        if _SHA256_RE.match(norm):
            _add(TiIndicator("sha256", norm))

    qr_payload = None
    if analysis_results:
        for result in analysis_results:
            analyzer = getattr(result, "analyzer", "")
            if analyzer == "qr_analysis":
                qr_payload = getattr(result, "payload", None)
                break
    _extract_from_payload(qr_payload, out, seen)

    if findings:
        for finding in findings:
            if len(out) >= limit:
                break
            _extract_from_finding(finding, out, seen)

    return out


def filter_by_type(
    indicators: Iterable[TiIndicator], indicator_type: str
) -> list[TiIndicator]:
    return [ind for ind in indicators if ind.type == indicator_type]


def coerce_for_provider(
    indicators: Iterable[TiIndicator], indicator_type: str
) -> list[TiIndicator]:
    """Provider-side pre-filter (e.g. IPs only for AbuseIPDB, public only)."""
    out: list[TiIndicator] = []
    for ind in indicators:
        if ind.type != indicator_type:
            continue
        if indicator_type == "ip" and not is_public_ip(ind.value):
            continue
        out.append(ind)
    return out