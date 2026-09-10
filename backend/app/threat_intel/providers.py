"""External TI provider clients - reputation lookups only, fail-safe.

Providers NEVER raise out of :meth:`lookup`; every outcome is returned as a
bounded :class:`TiLookup` with an explicit status. Guarantees:

- AbuseIPDB: CHECK endpoint only (reputation) - SANDBox never REPORTs,
- VirusTotal: reputation lookups only - SHA-256 file lookup by default, the
  file bytes/URL are NEVER submitted (URL lookup uses the deterministic VT URL
  id ``base64url(url)`` and does not auto-submit on 404),
- conservative shared rate limiting (see ``rate_limit``),
- HTTP 429 with ``Retry-After`` -> one bounded retry when the wait is small,
- no infinite retries, no retry storms,
- API keys live only in request headers, never in logs or results.
"""

from __future__ import annotations

import base64
import logging
import time
from typing import Any

import httpx

from app.threat_intel.models import IndicatorType, LookupStatus, TiLookup
from app.threat_intel.rate_limit import RateLimiter, default_limiter
from app.threat_intel.extraction import TiIndicator
from app.threat_intel.normalization import is_public_ip

logger = logging.getLogger(__name__)


class TiProviderError(Exception):
    """Base error for the provider layer (converted to a status, never raised)."""


class TiTimeoutError(TiProviderError):
    """Request exceeded the configured timeout."""


class TiUnavailableError(TiProviderError):
    """Provider not reachable / returned a server error."""


class TiRateLimitError(TiProviderError):
    def __init__(self, retry_after_s: int | None = None) -> None:
        super().__init__("rate limited")
        self.retry_after_s = retry_after_s


class TiOutputError(TiProviderError):
    """Provider response was not parseable sanitizable."""


def _now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _engines_total(stats: dict) -> int:
    if not isinstance(stats, dict):
        return 0
    return sum(int(v) for v in stats.values() if isinstance(v, (int, float)))


def _reputation_percent(malicious: int | None, total: int | None) -> float | None:
    if malicious is None or not total:
        return None
    return round((malicious / total) * 100.0, 1)


def _vt_status_label(stats: dict) -> str:
    if not isinstance(stats, dict):
        return "unknown"
    if int(stats.get("malicious") or 0) > 0:
        return "malicious"
    if int(stats.get("suspicious") or 0) > 0:
        return "suspicious"
    harmless = int(stats.get("harmless") or 0)
    undetected = int(stats.get("undetected") or 0)
    if (harmless + undetected) > 0:
        return "clean"
    return "unknown"


# ---------------------------------------------------------------------------
# AbuseIPDB
# ---------------------------------------------------------------------------


class AbuseIpDbProvider:
    name = "abuseipdb"

    def __init__(
        self,
        *,
        api_key: str = "",
        base_url: str = "",
        timeout_s: float | None = None,
        max_age_days: int = 90,
        max_requests_per_day: int = 1000,
        min_spacing_s: float = 1.0,
        limiter: RateLimiter | None = None,
        http: httpx.Client | None = None,
        max_retry_wait_s: float = 10.0,
    ) -> None:
        from app.core.config import settings

        self._api_key = api_key or settings.abuseipdb_api_key or ""
        self._base_url = (base_url or settings.abuseipdb_base_url).rstrip("/")
        self._timeout = timeout_s if timeout_s is not None else settings.abuseipdb_timeout_seconds
        self._max_age_days = max_age_days if max_age_days is not None else settings.abuseipdb_max_age_days
        self._max_per_day = max_requests_per_day if max_requests_per_day else settings.abuseipdb_max_requests_per_day
        self._min_spacing = min_spacing_s if min_spacing_s else settings.abuseipdb_min_spacing_s
        self._max_retry_wait = max_retry_wait_s if max_retry_wait_s else settings.ti_max_retry_wait_s
        self.limiter = limiter if limiter is not None else default_limiter()
        self._http = http if http is not None else httpx.Client(timeout=self._timeout)

    def supports_type(self, indicator_type: str) -> bool:
        return indicator_type == IndicatorType.IP.value

    def lookup(self, indicator: TiIndicator) -> TiLookup:
        itype = IndicatorType.IP.value
        base = TiLookup(
            provider=self.name,
            indicator_type=itype,
            indicator=indicator.value,
            provider_timestamp=_now_iso(),
        )
        if indicator.type == itype and not is_public_ip(indicator.value):
            base.status = LookupStatus.SKIPPED
            base.message = "ip not public - skipped"
            return base
        if not self._api_key:
            base.status = LookupStatus.SKIPPED
            base.message = "abuseipdb api key not configured"
            return base
        spacing = self.limiter.spacing_s_for(60, self._min_spacing)
        allowed, retry_after = self.limiter.acquire(
            self.name, per_minute=60, per_day=self._max_per_day, spacing_s=spacing
        )
        if not allowed:
            base.status = LookupStatus.RATE_LIMITED
            base.retry_after_s = retry_after
            base.message = "rate limit not available yet"
            return base

        params = {
            "ipAddress": indicator.value,
            "maxAgeInDays": str(int(self._max_age_days)),
        }
        headers = {"Key": self._api_key, "Accept": "application/json"}

        for attempt in range(2):  # max 1 retry, bounded
            try:
                response = self._http.get(
                    f"{self._base_url}/check", params=params, headers=headers,
                    timeout=self._timeout,
                )
            except httpx.TimeoutException as exc:
                base.status = LookupStatus.UNAVAILABLE
                base.message = f"timeout: {exc.__class__.__name__}"
                return base
            except httpx.HTTPError as exc:
                base.status = LookupStatus.UNAVAILABLE
                base.message = f"network_error: {exc.__class__.__name__}"
                return base

            if response.status_code == 429:
                retry = self._parse_retry_after(response)
                if attempt == 0 and retry is not None and retry <= self._max_retry_wait:
                    time.sleep(retry)  # bounded, single retry
                    continue
                base.status = LookupStatus.RATE_LIMITED
                base.retry_after_s = retry
                return base
            if response.status_code in (403, 401):
                base.status = LookupStatus.ERROR
                base.message = "forbidden: check API key"
                return base
            if response.status_code >= 500:
                base.status = LookupStatus.UNAVAILABLE
                base.message = f"http {response.status_code}"
                return base
            if response.status_code != 200:
                base.status = LookupStatus.ERROR
                base.message = f"http {response.status_code}"
                return base
            return self._parse(response.json(), base)

        base.status = LookupStatus.RATE_LIMITED
        return base

    def _parse(self, payload: Any, base: TiLookup) -> TiLookup:
        try:
            data = payload["data"]
        except (KeyError, TypeError, ValueError) as exc:
            base.status = LookupStatus.ERROR
            base.message = "malformed response"
            return base
        if not isinstance(data, dict):
            base.status = LookupStatus.ERROR
            base.message = "malformed response"
            return base

        score = data.get("abuseConfidenceScore")
        score = int(score) if isinstance(score, (int, float)) and not isinstance(score, bool) else 0
        score = max(0, min(100, score))

        reports = data.get("totalReports")
        reports = int(reports) if isinstance(reports, (int, float)) and not isinstance(reports, bool) else 0
        users = data.get("numDistinctUsers")
        users = int(users) if isinstance(users, (int, float)) and not isinstance(users, bool) else 0
        last = data.get("lastReportedAt")
        last = str(last)[:64] if last else None

        if score >= 75:
            label = "malicious"
        elif score >= 40:
            label = "suspicious"
        elif score > 0:
            label = "watch"
        else:
            label = "clean"

        base.status = LookupStatus.SUCCESS
        base.reputation = float(score)
        base.reports = reports
        base.distinct_users = users
        base.malicious = reports
        base.status_label = label
        base.first_seen = None
        base.last_seen = last
        base.confidence = round(score / 100.0, 3)
        categories: list[str] = []
        usage = data.get("usageType")
        if isinstance(usage, str) and usage:
            categories.append(usage[:64])
        if data.get("isTor") is True:
            categories.append("tor")
        base.categories = categories[:20]
        return base

    @staticmethod
    def _parse_retry_after(response: httpx.Response) -> int | None:
        header = response.headers.get("Retry-After")
        if header is None or not header:
            return None
        try:
            return max(1, int(header))
        except (ValueError, TypeError):
            return None


# ---------------------------------------------------------------------------
# VirusTotal
# ---------------------------------------------------------------------------


class VirusTotalProvider:
    name = "virustotal"

    def __init__(
        self,
        *,
        api_key: str = "",
        base_url: str = "",
        timeout_s: float | None = None,
        lookup_ip: bool | None = None,
        lookup_url: bool | None = None,
        lookup_domain: bool | None = None,
        lookup_sha256: bool | None = None,
        max_requests_per_minute: int | None = None,
        max_requests_per_day: int | None = None,
        min_spacing_s: float | None = None,
        limiter: RateLimiter | None = None,
        http: httpx.Client | None = None,
        max_retry_wait_s: float = 10.0,
    ) -> None:
        from app.core.config import settings

        self._api_key = api_key or settings.virustotal_api_key or ""
        self._base_url = (base_url or settings.virustotal_base_url).rstrip("/")
        self._timeout = timeout_s if timeout_s is not None else settings.virustotal_timeout_seconds
        self._flags = {
            IndicatorType.IP.value: lookup_ip if lookup_ip is not None else settings.virustotal_lookup_ip,
            IndicatorType.URL.value: lookup_url if lookup_url is not None else settings.virustotal_lookup_url,
            IndicatorType.DOMAIN.value: lookup_domain if lookup_domain is not None else settings.virustotal_lookup_domain,
            IndicatorType.SHA256.value: lookup_sha256 if lookup_sha256 is not None else settings.virustotal_lookup_sha256,
        }
        self._per_minute = (
            max_requests_per_minute if max_requests_per_minute else settings.virustotal_max_requests_per_minute
        )
        self._per_day = (
            max_requests_per_day if max_requests_per_day else settings.virustotal_max_requests_per_day
        )
        self._min_spacing = (
            min_spacing_s if min_spacing_s is not None else settings.virustotal_min_spacing_s
        )
        self._max_retry_wait = max_retry_wait_s if max_retry_wait_s else settings.ti_max_retry_wait_s
        self.limiter = limiter if limiter is not None else default_limiter()
        self._http = http if http is not None else httpx.Client(timeout=self._timeout)

    def supports_type(self, indicator_type: str) -> bool:
        return bool(self._flags.get(indicator_type))

    def lookup(self, indicator: TiIndicator) -> TiLookup:
        itype = indicator.type
        base = TiLookup(
            provider=self.name,
            indicator_type=itype,
            indicator=indicator.value,
            provider_timestamp=_now_iso(),
        )
        if indicator.type == IndicatorType.IP.value and not is_public_ip(indicator.value):
            base.status = LookupStatus.SKIPPED
            base.message = "ip not public - skipped"
            return base
        if not self._api_key:
            base.status = LookupStatus.SKIPPED
            base.message = "virustotal api key not configured"
            return base
        spacing = self.limiter.spacing_s_for(self._per_minute, self._min_spacing)
        allowed, retry_after = self.limiter.acquire(
            self.name,
            per_minute=self._per_minute,
            per_day=self._per_day,
            spacing_s=spacing,
        )
        if not allowed:
            base.status = LookupStatus.RATE_LIMITED
            base.retry_after_s = retry_after
            base.message = "rate limit not available yet"
            return base

        path, params = self._endpoint(indicator)
        headers = {"x-apikey": self._api_key}

        for attempt in range(2):  # max 1 retry, bounded
            try:
                response = self._http.get(
                    f"{self._base_url}/{path}", params=params, headers=headers, timeout=self._timeout
                )
            except httpx.TimeoutException as exc:
                base.status = LookupStatus.UNAVAILABLE
                base.message = f"timeout: {exc.__class__.__name__}"
                return base
            except httpx.HTTPError as exc:
                base.status = LookupStatus.UNAVAILABLE
                base.message = f"network_error: {exc.__class__.__name__}"
                return base

            if response.status_code == 429:
                retry = self._parse_retry_after(response)
                if attempt == 0 and retry is not None and retry <= self._max_retry_wait:
                    time.sleep(retry)
                    continue
                base.status = LookupStatus.RATE_LIMITED
                base.retry_after_s = retry
                return base
            if response.status_code == 404:
                base.status = LookupStatus.NOT_FOUND
                base.message = "no record"
                return base
            if response.status_code in (403, 401):
                base.status = LookupStatus.ERROR
                base.message = "forbidden: check API key"
                return base
            if response.status_code >= 500:
                base.status = LookupStatus.UNAVAILABLE
                base.message = f"http {response.status_code}"
                return base
            if response.status_code != 200:
                base.status = LookupStatus.ERROR
                base.message = f"http {response.status_code}"
                return base
            return self._parse(response.json(), base)

        base.status = LookupStatus.RATE_LIMITED
        return base

    def _endpoint(self, indicator: TiIndicator) -> tuple[str, dict]:
        if indicator.type == IndicatorType.IP.value:
            return f"ip_addresses/{indicator.value}", {}
        if indicator.type == IndicatorType.DOMAIN.value:
            return f"domains/{indicator.value}", {}
        if indicator.type == IndicatorType.SHA256.value:
            return f"files/{indicator.value}", {}
        # URL: deterministic VT URL id - unpadded URL-safe base64 of the URL
        # itself (RFC 4648 section 3.2), which the VirusTotal v3 /urls/{id}
        # endpoint accepts (it canonizes server-side). base64 of the SHA-256
        # digest is NOT a valid URL identifier and is rejected with HTTP 400.
        # If the URL was never submitted/seen the provider answers 404 ->
        # not_found; we NEVER auto-submit the URL.
        url_id = base64.urlsafe_b64encode(indicator.value.encode("utf-8")).decode("ascii").rstrip("=")
        return f"urls/{url_id}", {}

    def _parse(self, payload: Any, base: TiLookup) -> TiLookup:
        if not isinstance(payload, dict) or not isinstance(payload.get("data"), dict):
            base.status = LookupStatus.ERROR
            base.message = "malformed response"
            return base
        data = payload["data"]
        if not isinstance(data, dict):
            base.status = LookupStatus.ERROR
            base.message = "malformed response"
            return base
        attributes = data.get("attributes")
        if not isinstance(attributes, dict):
            base.status = LookupStatus.ERROR
            base.message = "malformed response"
            return base

        stats = attributes.get("last_analysis_stats")
        if not isinstance(stats, dict):
            stats = {}
        malicious = int(stats.get("malicious") or 0)
        suspicious = int(stats.get("suspicious") or 0)
        harmless = int(stats.get("harmless") or 0)
        undetected = int(stats.get("undetected") or 0)
        total = _engines_total(stats)

        base.status = LookupStatus.SUCCESS
        base.malicious = malicious
        base.suspicious = suspicious
        base.clean = harmless
        base.undetected = undetected
        base.total_engines = total
        base.reputation = _reputation_percent(malicious, total)
        base.status_label = _vt_status_label(stats)

        # Bounded first/last seen from submission/analysis timestamps.
        first = attributes.get("first_submission_date") or attributes.get("last_analysis_date")
        last = attributes.get("last_submission_date") or attributes.get("last_modification_date")
        if first is not None:
            try:
                base.first_seen = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(int(first)))
            except (ValueError, TypeError, OverflowError):
                base.first_seen = None
        if last is not None:
            try:
                base.last_seen = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(int(last)))
            except (ValueError, TypeError, OverflowError):
                base.last_seen = None

        categories: list[str] = []
        cats = attributes.get("categories")
        if isinstance(cats, dict):
            categories.extend(str(v)[:64] for v in cats.values() if isinstance(v, str))
        tags = attributes.get("tags")
        if isinstance(tags, list):
            categories.extend(str(t)[:64] for t in tags if isinstance(t, str))
        base.categories = categories[:20]

        reputation_raw = attributes.get("reputation")
        if isinstance(reputation_raw, (int, float)) and not isinstance(reputation_raw, bool):
            # VT's signed reputation (-100..100) - expose as an informational
            # number; the percentage above stays the primary signal.
            base.message = f"vt_reputation={int(reputation_raw)}"
        return base

    @staticmethod
    def _parse_retry_after(response: httpx.Response) -> int | None:
        header = response.headers.get("Retry-After")
        if header is None or not header:
            return None
        try:
            return max(1, int(header))
        except (ValueError, TypeError):
            return None


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------


def build_providers(
    *,
    limiter: RateLimiter | None = None,
    http: httpx.Client | None = None,
    max_retry_wait_s: float | None = None,
) -> list:
    """Build the enabled providers from current configuration.

    A provider is instantiated only when its toggle is on AND a key is present;
    otherwise it is simply omitted (no code path touches a missing key).
    """
    from app.core.config import settings

    providers: list = []
    retry_wait = max_retry_wait_s if max_retry_wait_s is not None else settings.ti_max_retry_wait_s
    if settings.abuseipdb_enabled and settings.abuseipdb_api_key:
        providers.append(
            AbuseIpDbProvider(limiter=limiter, http=http, max_retry_wait_s=retry_wait)
        )
    if settings.virustotal_enabled and settings.virustotal_api_key:
        providers.append(
            VirusTotalProvider(limiter=limiter, http=http, max_retry_wait_s=retry_wait)
        )
    return providers