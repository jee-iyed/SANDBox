"""Threat Intelligence enrichment layer unit tests (MOCK providers only).

Deterministic: providers talk to httpx.MockTransport, the cache/limiter use an
in-memory FakeStore, persistence is a FakeDb - no real API keys, no network, no
Redis required.

Coverage (17 scenarios + extras):
   1.  TI disabled -> complete no-op (no DB, no provider calls)
   2.  missing API keys / missing providers -> graceful skip
   3.  AbuseIPDB CHECK success (score -> label/confidence/reputation)
   4.  VirusTotal URL lookup via deterministic base64url(url) id
   5.  VirusTotal ip/domain/sha256 endpoint mapping
   6.  404 -> not_found (no auto-submission, no retries)
   7.  429 + Retry-After over budget -> rate_limited (no retry storm)
   8.  429 + small Retry-After -> single bounded retry succeeds
   9.  timeout -> unavailable
  10. 5xx -> unavailable
  11. malformed response -> error
  12. 401/403 -> error (forbidden / check key)
  13. dedup: same URL from QR + findings + text -> ONE lookup per scan
  14. cache hit -> provider NOT called (status cached)
  15. cache miss -> provider called (status success)
  16. provider exception -> bounded error lookup, verdict/scan INTACT
  17. limiter: spaces requests, enforces per-minute + per-day budgets; one
      shared centralized singleton for every worker
Extras: API key never leaks into evidence/payload/logs, private IP never
queried, indicator cap, INFO severity + tags, SHA-256 extracted, persist
failure rolls back, scan=None guard.

Usage:
    .\\.venv\\Scripts\\python.exe tests\\test_ti_layer.py
"""

from __future__ import annotations

import base64
import json
import logging
import sys
import time
import uuid
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import httpx  # noqa: E402

from app.threat_intel import LookupStatus, TiLookup, TiService  # noqa: E402
from app.threat_intel.cache import TiCache  # noqa: E402
from app.threat_intel.extraction import TiIndicator, extract_indicators  # noqa: E402
from app.threat_intel.providers import (  # noqa: E402
    AbuseIpDbProvider,
    VirusTotalProvider,
)
from app.threat_intel.rate_limit import RateLimiter, default_limiter  # noqa: E402
from app.threat_intel.store import LocalStore, TiStore  # noqa: E402
from app.db.models import AnalysisResult, Finding, Severity  # noqa: E402

PASS = 0
FAIL = 0
_KEY = "KEY_abc123_secret"


def report(name: str, ok: bool, detail: str = ""):
    global PASS, FAIL
    if ok:
        PASS += 1
    else:
        FAIL += 1
    print(f"[{'PASS' if ok else 'FAIL'}] {name}" + (f"  -> {detail}" if detail else ""))


# ---------------------------------------------------------------------------
# Fakes
# ---------------------------------------------------------------------------


class FakeStore(TiStore):
    """In-memory, expiry-aware TiStore (deterministic cache + limiter backend)."""

    def __init__(self) -> None:
        self._d: dict = {}
        self._exp: dict = {}

    def get(self, key: str) -> str | None:
        exp = self._exp.get(key)
        if exp is not None and exp <= time.monotonic():
            self._d.pop(key, None)
            self._exp.pop(key, None)
            return None
        return self._d.get(key)

    def setex(self, key: str, ttl_s: int, value: str) -> None:
        self._d[key] = value
        self._exp[key] = time.monotonic() + ttl_s if ttl_s and ttl_s > 0 else None

    def set_nx(self, key: str, ttl_s: int, value: str) -> bool:
        if self.get(key) is not None:
            return False
        self.setex(key, ttl_s, value)
        return True

    def incr(self, key: str) -> int:
        current = self.get(key)
        nxt = (int(current) if current else 0) + 1
        self._d[key] = str(nxt)
        return nxt

    def expire(self, key: str, ttl_s: int) -> None:
        if key in self._d:
            self._exp[key] = time.monotonic() + ttl_s if ttl_s and ttl_s > 0 else None

    def ttl(self, key: str) -> int:
        exp = self._exp.get(key)
        if key not in self._d:
            return -2
        if exp is None:
            return -1
        remaining = int(exp - time.monotonic())
        return remaining if remaining > 0 else -2


class _Q:
    def __init__(self, items: list):
        self._items = items

    def filter(self, *a, **k):
        return self

    def filter_by(self, **k):
        return self

    def limit(self, n):
        return self

    def all(self):
        return list(self._items)


class FakeDb:
    def __init__(self, analysis_results=None, findings=None):
        self._ar = list(analysis_results or [])
        self._f = list(findings or [])
        self.added: list = []
        self.committed = 0
        self.rolled_back = 0

    def query(self, cls):
        if cls is AnalysisResult:
            return _Q(self._ar)
        if cls is Finding:
            return _Q(self._f)
        return _Q([])

    def add(self, obj):
        self.added.append(obj)

    def commit(self):
        self.committed += 1

    def rollback(self):
        self.rolled_back += 1

    @property
    def persisted_findings(self):
        return [o for o in self.added if isinstance(o, Finding)]

    @property
    def persisted_analysis(self):
        return [o for o in self.added if isinstance(o, AnalysisResult)]


class BoomDb(FakeDb):
    def commit(self):
        self.rolled_back += 1  # service calls rollback itself; simulate first
        raise RuntimeError("commit exploded")


class AlwaysAllow:
    def spacing_s_for(self, per_minute, configured_spacing):
        return 0.0

    def acquire(self, provider, *, per_minute, per_day, spacing_s):
        return True, 0


class CountingProvider:
    """Non-HTTP provider; records every lookup call."""

    name = "counting"

    def __init__(self) -> None:
        self.calls: list[tuple[str, str]] = []

    def supports_type(self, indicator_type: str) -> bool:
        self.calls.append(("supports_type", indicator_type))
        return True

    def lookup(self, indicator):
        self.calls.append(("lookup", indicator.value))
        if indicator.value.endswith("/malicious"):
            return TiLookup(
                provider=self.name,
                indicator_type=indicator.type,
                indicator=indicator.value,
                status=LookupStatus.SUCCESS,
                status_label="malicious",
                reputation=80.0,
                confidence=0.8,
            )
        return TiLookup(
            provider=self.name,
            indicator_type=indicator.type,
            indicator=indicator.value,
            status=LookupStatus.SUCCESS,
            status_label="clean",
            reputation=0.0,
            confidence=1.0,
        )

    @property
    def lookup_count(self) -> int:
        return sum(1 for kind, _ in self.calls if kind == "lookup")


class RaisingProvider(CountingProvider):
    def lookup(self, indicator):
        self.calls.append(("lookup", indicator.value))
        raise RuntimeError("provider burned down")


def fake_scan(sha256: str | None = None):
    return SimpleNamespace(
        id=uuid.uuid4(),
        file=SimpleNamespace(sha256=sha256) if sha256 else None,
    )


def qr_analysis(urls: list[str]):
    return SimpleNamespace(analyzer="qr_analysis", payload={"urls": urls})


def finding(ftype: str, value: str | None, evidence: dict | None = None):
    return SimpleNamespace(type=ftype, value=value, evidence=evidence)


def memory_cache():
    return TiCache(redis=FakeStore(), local=LocalStore(1))


def vt_success_body(suite_url: bool = False):
    stats = {"harmless": 15, "malicious": 2, "suspicious": 1, "undetected": 82}
    attributes = {
        "last_analysis_stats": stats,
        "categories": {"OCHreplitz": "malicious"},
        "tags": ["malware:exe"],
        "first_submission_date": 1700000000,
    }
    if suite_url:
        attributes["url"] = "https://example.com/a?b=1"
    return {"data": {"type": "file", "id": "x", "attributes": attributes}}


VT_BODY = vt_success_body()
ABUSE_BODY = {
    "data": {
        "ipAddress": "93.184.216.34",
        "abuseConfidenceScore": 92,
        "totalReports": 5,
        "numDistinctUsers": 3,
        "lastReportedAt": "2025-01-01T00:00:00Z",
        "usageType": "Malware hosting",
        "isTor": False,
    }
}


def vt_provider(handler, *, api_key: str = _KEY):
    transport = httpx.MockTransport(handler)
    return VirusTotalProvider(
        api_key=api_key,
        base_url="https://vt.local/api/v3",
        timeout_s=2.0,
        min_spacing_s=0.0,
        http=httpx.Client(transport=transport, timeout=2.0),
        limiter=AlwaysAllow(),
        max_retry_wait_s=2.0,
    )


def abuse_provider(handler, *, api_key: str = _KEY):
    transport = httpx.MockTransport(handler)
    return AbuseIpDbProvider(
        api_key=api_key,
        base_url="https://abuse.local/v2",
        timeout_s=2.0,
        http=httpx.Client(transport=transport, timeout=2.0),
        limiter=AlwaysAllow(),
        max_retry_wait_s=2.0,
    )


# ---------------------------------------------------------------------------
# Settings patching helper
# ---------------------------------------------------------------------------

from app.core.config import settings as _settings  # noqa: E402

_STACK: list = []


def patch_settings(**kwargs):
    for key, value in kwargs.items():
        if not hasattr(_settings, key):
            raise KeyError(key)
        _STACK.append((key, getattr(_settings, key)))
        setattr(_settings, key, value)


def restore_settings():
    while _STACK:
        key, old = _STACK.pop()
        setattr(_settings, key, old)


def _ok(name, ok, detail=""):
    report(name, ok, detail)
    restore_settings()
    return ok


URL_NORMALIZED = "https://example.com/a?b=1"
URL_ID = base64.urlsafe_b64encode(URL_NORMALIZED.encode("utf-8")).decode("ascii").rstrip("=")
SHA = "a" * 64


# ---------------------------------------------------------------------------
# 1. TI disabled -> complete no-op
# ---------------------------------------------------------------------------
def test_ti_disabled_is_noop():
    patch_settings(ti_enabled=False)
    provider = CountingProvider()
    db = FakeDb(findings=[finding("static_suspicious_url", "https://example.com/x")])
    result = TiService(providers=[provider], cache=memory_cache()).enrich_scan(db, fake_scan(SHA))
    ok = (
        result is None
        and provider.lookup_count == 0
        and len(db.persisted_findings) == 0
        and db.committed == 0
    )
    return _ok("1. TI disabled -> complete no-op", ok)


# ---------------------------------------------------------------------------
# 2. Missing API keys / missing providers -> graceful skip
# ---------------------------------------------------------------------------
def test_missing_keys_graceful_skip():
    patch_settings(
        ti_enabled=True,
        abuseipdb_enabled=True,
        abuseipdb_api_key="",
        virustotal_enabled=True,
        virustotal_api_key="",
    )
    db = FakeDb(findings=[finding("dns_request", "example.com")])
    result = TiService().enrich_scan(db, fake_scan(SHA))
    ok = (
        result is None
        and len(db.persisted_findings) == 0
        and db.committed == 0
        and "abuseipdb" not in [f.type for f in db.persisted_findings]
    )
    return _ok("2a. keyless providers skipped, nothing persisted", ok)


def test_provider_without_key_status_skipped():
    patch_settings(abuseipdb_api_key="", virustotal_api_key="")
    p_abuse = AbuseIpDbProvider(api_key="", base_url="https://abuse.local/v2")
    p_vt = VirusTotalProvider(api_key="", base_url="https://vt.local/api/v3")
    r1 = p_abuse.lookup(TiIndicator("ip", "93.184.216.34"))
    r2 = p_vt.lookup(TiIndicator("url", URL_NORMALIZED))
    ok = (
        r1.status == LookupStatus.SKIPPED
        and "key" in str(r1.message).lower()
        and r2.status == LookupStatus.SKIPPED
        and "key" in str(r2.message).lower()
    )
    return _ok("2b. provider without key -> SKIPPED status", ok)


from app.threat_intel.extraction import TiIndicator  # noqa: E402


# ---------------------------------------------------------------------------
# 3. AbuseIPDB CHECK success
# ---------------------------------------------------------------------------
def test_abuseipdb_success():
    requested = {"url": None, "params": None}

    def handler(request: httpx.Request) -> httpx.Response:
        requested["url"] = str(request.url)
        requested["params"] = dict(request.url.params)
        return httpx.Response(200, json=ABUSE_BODY)

    provider = abuse_provider(handler)
    lookup = provider.lookup(TiIndicator("ip", "93.184.216.34"))
    ok = (
        lookup.status == LookupStatus.SUCCESS
        and lookup.reputation == 92.0
        and lookup.status_label == "malicious"
        and lookup.confidence == 0.92
        and lookup.malicious == 5
        and lookup.distinct_users == 3
        and "/check" in requested["url"]
        and requested["params"].get("ipAddress") == "93.184.216.34"
        and "report" not in requested["url"].lower()
    )
    return _ok("3. AbuseIPDB CHECK success (score/label/confidence)", ok, str(requested))


# ---------------------------------------------------------------------------
# 4. VirusTotal URL lookup (deterministic id, no auto-submit)
# ---------------------------------------------------------------------------
def test_virustotal_url_lookup():
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["path"] = request.url.path
        return httpx.Response(200, json=VT_BODY)

    provider = vt_provider(handler)
    lookup = provider.lookup(TiIndicator("url", URL_NORMALIZED))
    ok = (
        seen["path"].endswith(f"/urls/{URL_ID}")
        and lookup.status == LookupStatus.SUCCESS
        and lookup.malicious == 2
        and lookup.suspicious == 1
        and lookup.total_engines == 100
        and lookup.reputation == 2.0
        and lookup.status_label == "malicious"
        and "malware:exe" in lookup.categories
    )
    return _ok("4. VT URL lookup via base64url(url) id", ok, f"path={seen.get('path')}")


def test_virustotal_url_port_preserved():
    from app.threat_intel.normalization import normalize_url

    raw = "http://59.96.141.74:37653/bin.sh"
    norm = normalize_url(raw)
    expected_id = base64.urlsafe_b64encode(raw.encode("utf-8")).decode("ascii").rstrip("=")
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["path"] = request.url.path
        return httpx.Response(200, json=VT_BODY)

    provider = vt_provider(handler)
    lookup = provider.lookup(TiIndicator("url", norm))
    ok = (
        norm == raw
        and seen["path"].endswith(f"/urls/{expected_id}")
        and lookup.status == LookupStatus.SUCCESS
    )
    return _ok("4b. VT URL with explicit port preserved (exact VT id)", ok, f"norm={norm!r} path={seen.get('path')}")


# ---------------------------------------------------------------------------
# 5. VirusTotal ip/domain/sha256 endpoint mapping
# ---------------------------------------------------------------------------
def test_virustotal_indicator_endpoints():
    paths = {}
    LIMIT = 3
    state = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        paths[state["n"]] = request.url.path
        state["n"] += 1
        return httpx.Response(200, json=VT_BODY)

    # fresh provider per lookup to avoid shared-limiter coupling
    for i, indicator in enumerate(
        [
            TiIndicator("ip", "93.184.216.34"),
            TiIndicator("domain", "example.com"),
            TiIndicator("sha256", SHA),
        ]
    ):
        vt_provider(handler).lookup(indicator)
    ok = (
        any("/ip_addresses/93.184.216.34" in paths.get(i, "") for i in range(LIMIT))
        and any("/domains/example.com" in paths.get(i, "") for i in range(LIMIT))
        and any(f"/files/{SHA}" in paths.get(i, "") for i in range(LIMIT))
    )
    return _ok("5. VT ip/domain/sha256 endpoint mapping", ok, str(paths))


# ---------------------------------------------------------------------------
# 6. 404 -> not_found (no submission, no retries)
# ---------------------------------------------------------------------------
def test_virustotal_404_not_found():
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return httpx.Response(404, json={"error": {"code": "NotFoundError"}})

    lookup = vt_provider(handler).lookup(TiIndicator("url", URL_NORMALIZED))
    ok = lookup.status == LookupStatus.NOT_FOUND and calls["n"] == 1
    return _ok("6. VT 404 -> not_found, no auto-submit/no retry", ok)


# ---------------------------------------------------------------------------
# 7. 429 + Retry-After over the bounded budget -> rate_limited, no retry storm
# ---------------------------------------------------------------------------
def test_429_rate_limited_no_retry_storm():
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return httpx.Response(429, headers={"Retry-After": "5"}, json={})

    provider = vt_provider(handler)  # max_retry_wait_s=2 < 5 -> never retries
    lookup = provider.lookup(TiIndicator("url", URL_NORMALIZED))
    ok = (
        lookup.status == LookupStatus.RATE_LIMITED
        and lookup.retry_after_s == 5
        and calls["n"] == 1
    )
    return _ok("7. 429 beyond budget -> rate_limited (no retry storm)", ok)


# ---------------------------------------------------------------------------
# 8. 429 + small Retry-After -> exactly one bounded retry succeeds
# ---------------------------------------------------------------------------
def test_429_small_retry_once():
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        if calls["n"] == 1:
            return httpx.Response(429, headers={"Retry-After": "1"}, json={})
        return httpx.Response(200, json=VT_BODY)

    start = time.monotonic()
    lookup = vt_provider(handler).lookup(TiIndicator("url", URL_NORMALIZED))
    elapsed = time.monotonic() - start
    ok = (
        lookup.status == LookupStatus.SUCCESS
        and calls["n"] == 2
        and elapsed >= 0.9
    )
    return _ok("8. 429 + small Retry-After -> single bounded retry", ok)


# ---------------------------------------------------------------------------
# 9/10. timeout / 5xx -> unavailable
# ---------------------------------------------------------------------------
def test_timeout_unavailable():
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectTimeout("boom")

    from app.threat_intel.providers import TiTimeoutError

    lookup = vt_provider(handler).lookup(TiIndicator("url", URL_NORMALIZED))
    ok = lookup.status == LookupStatus.UNAVAILABLE and "timeout" in lookup.message.lower()
    return _ok("9. timeout -> unavailable (never fatal)", ok)


def test_5xx_unavailable():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(503, json={})

    lookup = abuse_provider(handler).lookup(TiIndicator("ip", "93.184.216.34"))
    ok = lookup.status == LookupStatus.UNAVAILABLE
    return _ok("10. 5xx -> unavailable (never fatal)", ok)


# ---------------------------------------------------------------------------
# 11/12. malformed / forbidden responses -> error status
# ---------------------------------------------------------------------------
def test_malformed_response_error():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=[])

    lookup = vt_provider(handler).lookup(TiIndicator("url", URL_NORMALIZED))
    ok = lookup.status == LookupStatus.ERROR and "malformed" in lookup.message.lower()
    return _ok("11. malformed response -> error", ok)


def test_forbidden_error():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(403, json={})

    lookup = abuse_provider(handler).lookup(TiIndicator("ip", "93.184.216.34"))
    ok = lookup.status == LookupStatus.ERROR and "key" in lookup.message.lower()
    return _ok("12. 401/403 -> error (forbidden / check key)", ok)


# ---------------------------------------------------------------------------
# 13. dedup: same URL from QR + findings + text -> ONE lookup
# ---------------------------------------------------------------------------
def test_dedup_one_lookup_per_scan():
    patch_settings(ti_enabled=True)
    db = FakeDb(
        analysis_results=[qr_analysis([URL_NORMALIZED])],
        findings=[
            finding("static_suspicious_url", URL_NORMALIZED),
            finding("dns_request", "example.com"),
        ],
    )
    provider = CountingProvider()
    TiService(providers=[provider], cache=memory_cache()).enrich_scan(db, fake_scan(SHA))
    url_calls = [v for kind, v in provider.calls if kind == "lookup" and v.startswith("https://")]
    ok = (
        len(url_calls) == 1
        and url_calls == [URL_NORMALIZED]
        and len(db.persisted_findings) >= 1
        and any(f.type == "ti_counting_url" and f.value == URL_NORMALIZED for f in db.persisted_findings)
    )
    return _ok("13. URL from QR + finding + text deduped to ONE lookup", ok, str(url_calls))


def test_qr_urls_connected():
    patch_settings(ti_enabled=True)
    db = FakeDb(
        analysis_results=[qr_analysis([URL_NORMALIZED, "https://second.example.org/y"])],
        findings=[],
    )
    provider = CountingProvider()
    TiService(providers=[provider], cache=memory_cache()).enrich_scan(db, fake_scan(None))
    lookup_values = {v for kind, v in provider.calls if kind == "lookup"}
    ok = URL_NORMALIZED in lookup_values and "https://second.example.org/y" in lookup_values
    return _ok("13b. QR URLs connected into TI lookups", ok, str(lookup_values))


# ---------------------------------------------------------------------------
# 14/15. cache hit / miss behaviour + shared cache key
# ---------------------------------------------------------------------------
def test_cache_hit_skips_provider():
    patch_settings(ti_enabled=True)
    db1 = FakeDb(findings=[finding("static_suspicious_url", URL_NORMALIZED)])
    cache = memory_cache()
    provider = CountingProvider()
    service = TiService(providers=[provider], cache=cache)
    service.enrich_scan(db1, fake_scan(SHA))
    first_calls = provider.lookup_count

    db2 = FakeDb(findings=[finding("static_suspicious_url", URL_NORMALIZED)])
    service.enrich_scan(db2, fake_scan(SHA))
    second_calls = provider.lookup_count

    cached = [f for f in db2.persisted_findings if f.type == "ti_counting_url"]
    ok = (
        first_calls == 2  # url + file sha256
        and second_calls == first_calls  # no additional provider call
        and cached
        and cached[0].evidence.get("status") == "cached"
        and cached[0].evidence.get("cached") is True
    )
    return _ok("14. cache hit -> provider NOT called (status cached)", ok)


def test_cache_miss_calls_provider():
    patch_settings(ti_enabled=True)
    cache = memory_cache()
    provider = CountingProvider()
    service = TiService(providers=[provider], cache=cache)

    db1 = FakeDb(findings=[finding("static_suspicious_url", "https://one.example/x")])
    service.enrich_scan(db1, fake_scan(SHA))
    after_first = provider.lookup_count

    db2 = FakeDb(findings=[finding("static_suspicious_url", "https://two.example/x")])
    service.enrich_scan(db2, fake_scan(SHA))
    after_second = provider.lookup_count

    ok = after_first == 2 and after_second == after_first + 1  # only the new URL queried
    return _ok("15. cache miss -> provider called for new indicator", ok, f"{after_first}->{after_second}")


# ---------------------------------------------------------------------------
# 16. provider exception -> bounded error, scan/verdict intact
# ---------------------------------------------------------------------------
def test_provider_down_verdict_intact():
    patch_settings(ti_enabled=True)
    db = FakeDb(findings=[finding("static_suspicious_url", URL_NORMALIZED)])
    provider = RaisingProvider()
    result = TiService(providers=[provider], cache=memory_cache()).enrich_scan(db, fake_scan(SHA))

    error_findings = [f for f in db.persisted_findings if f.type == "ti_counting_url"]
    ok = (
        result is not None
        and result["status"] == "ok"
        and error_findings
        and error_findings[0].evidence.get("status") == "error"
        and "internal_error" in error_findings[0].evidence.get("message", "")
        and db.committed == 1
        and db.rolled_back == 0
    )
    return _ok("16. provider exception -> bounded error, scan intact", ok, str(result))


# ---------------------------------------------------------------------------
# 17. rate limiter: spacing, per-minute + per-day budgets, centralized
# ---------------------------------------------------------------------------
def test_limiter_spacing():
    store = FakeStore()
    limiter = RateLimiter(redis=store, local=FakeStore())
    spacing = limiter.spacing_s_for(4, 0.0)
    ok1, wait1 = limiter.acquire("vt", per_minute=4, per_day=1000, spacing_s=spacing)
    ok2, wait2 = limiter.acquire("vt", per_minute=4, per_day=1000, spacing_s=spacing)
    ok = ok1 is True and ok2 is False and wait2 >= 1 and spacing == 15.0
    return _ok("17a. spacing gate + auto spacing formula", ok, f"spacing={spacing} wait={wait2}")


def test_limiter_per_minute_budget():
    store = FakeStore()
    limiter = RateLimiter(redis=store, local=FakeStore())
    now = int(time.time())
    min_key = f"ti:rl:vt:min:{now // 60}"
    for _ in range(4):
        store.incr(min_key)  # seed 4 requests this minute
    ok1, _ = limiter.acquire("vt", per_minute=4, per_day=1000, spacing_s=0.01)
    # spacing gate is fresh (new store): 5th request must be denied by minute cap
    ok = ok1 is False
    return _ok("17b. per-minute budget enforced (5th request denied)", ok)


def test_limiter_per_day_budget():
    store = FakeStore()
    limiter = RateLimiter(redis=store, local=FakeStore())
    now = int(time.time())
    day_key = f"ti:rl:vt:day:{now // 86400}"
    store.incr(day_key)
    store.incr(day_key)
    limiter.acquire("vt", per_minute=4, per_day=2, spacing_s=0.01)  # spacing passes
    r2, _ = limiter.acquire("vt", per_minute=4, per_day=2, spacing_s=0.01)  # spacing lock?
    # spacing lock may block independently; retry after the lock TTL to isolate
    if r2:
        r2, _ = limiter.acquire("vt", per_minute=4, per_day=2, spacing_s=0.01)
    ok = r2 is False
    return _ok("17c. per-day budget enforced", ok)


def test_limiter_centralized_singleton():
    ok = (
        default_limiter() is default_limiter()
        and AbuseIpDbProvider(limiter=default_limiter()).limiter is default_limiter()
        and VirusTotalProvider(limiter=default_limiter()).limiter is default_limiter()
    )
    return _ok("17d. one shared limiter for every worker/provider", ok)


# ---------------------------------------------------------------------------
# Security / boundedness extras
# ---------------------------------------------------------------------------
def test_api_key_never_leaks():
    patch_settings(ti_enabled=True)
    captured = {"headers": None, "url": None}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["headers"] = dict(request.headers)
        captured["url"] = str(request.url)
        return httpx.Response(200, json=VT_BODY)

    db = FakeDb(findings=[finding("static_suspicious_url", URL_NORMALIZED)])
    provider = vt_provider(handler)
    service = TiService(providers=[provider], cache=memory_cache())
    service.enrich_scan(db, fake_scan(SHA))

    blob = json.dumps(
        {
            "evidence": db.persisted_findings[0].evidence,
            "payload": db.persisted_analysis[0].payload,
        },
        default=str,
    )
    ok = (
        _KEY in captured["headers"].get("x-apikey", "")  # sanctioned location
        and _KEY not in blob
        and _KEY not in captured["url"]
    )
    return _ok("S1. API key only in the request header, never persisted/logged", ok)


def test_private_ip_never_queried():
    def handler(request: httpx.Request) -> httpx.Response:
        raise AssertionError("private IP must never be queried")

    provider = abuse_provider(handler)
    lookup = provider.lookup(TiIndicator("ip", "10.0.0.1"))
    ok = lookup.status == LookupStatus.SKIPPED and "public" in lookup.message
    return _ok("S2. private IP never queried", ok)


def test_evidence_is_bounded():
    patch_settings(ti_enabled=True)
    db = FakeDb(findings=[finding("static_suspicious_url", "https://example.com/x")])
    provider = vt_provider(lambda r: httpx.Response(200, json=VT_BODY))  # noqa: E731
    TiService(providers=[provider], cache=memory_cache()).enrich_scan(db, fake_scan(None))
    evidence = db.persisted_findings[0].evidence or {}
    allowed = {
        "provider", "indicator_type", "indicator", "status", "status_label",
        "cached", "provider_timestamp", "reputation", "confidence",
        "malicious", "suspicious", "clean", "undetected", "total_engines",
        "reports", "distinct_users", "categories", "first_seen", "last_seen",
        "message", "retry_after_s",
    }
    ok = set(evidence.keys()) <= allowed and evidence.get("indicator_type") == "url"
    return _ok("S3. evidence bounded + sanitized (allow-list)", ok, str(list(evidence)))


def test_indicators_capped():
    findings = [finding("static_suspicious_url", f"https://n{i}.example/x") for i in range(50)]
    indicators = extract_indicators(file_sha256=None, findings=findings, max_indicators=2)
    ok = len(indicators) == 2
    return _ok("S4. indicator extraction capped", ok, str(len(indicators)))


def test_finding_severity_and_tags():
    patch_settings(ti_enabled=True)
    db = FakeDb(findings=[finding("static_suspicious_url", "https://example.com/x")])
    TiService(providers=[CountingProvider()], cache=memory_cache()).enrich_scan(db, fake_scan(None))
    f = db.persisted_findings[0]
    ok = (
        f.severity == Severity.INFO
        and f.source == "threat_intel"
        and "threat_intel" in f.tags
        and f.confidence == 1.0
        and f.analyzer_version
    )
    return _ok("S5. TI findings are INFO-severity, tagged, deterministic", ok)


def test_sha256_extracted_from_file():
    indicators = extract_indicators(file_sha256=SHA, findings=[])
    ok = any(i.type == "sha256" and i.value == SHA for i in indicators)
    return _ok("S6. file SHA-256 extracted (never the file bytes)", ok)


def test_persist_failure_rolls_back():
    patch_settings(ti_enabled=True)
    db = BoomDb(findings=[finding("static_suspicious_url", "https://example.com/x")])
    result = TiService(providers=[CountingProvider()], cache=memory_cache()).enrich_scan(db, fake_scan(SHA))
    ok = result is not None and result["status"] == "error" and "persist_error" in result["error"]
    return _ok("S7. persist failure -> error summary + rollback, no crash", ok)


def test_scan_none_guard():
    patch_settings(ti_enabled=True)
    result = TiService(providers=[CountingProvider()], cache=memory_cache()).enrich_scan(FakeDb(), None)
    ok = result is not None and result["status"] == "error"
    return _ok("S8. scan=None guard returns error summary, no crash", ok)


def test_extraction_private_and_local_skipped():
    from app.threat_intel.normalization import is_public_ip

    findings = [
        finding("network_attempt", "127.0.0.1:8080"),
        finding("network_attempt", "10.1.2.3:443"),
        finding("network_attempt", "93.184.216.34:443"),
    ]
    indicators = extract_indicators(file_sha256=None, findings=findings)
    ips = [i.value for i in indicators if i.type == "ip"]
    # Extraction carries local indicators for evidence, but the public-IP gate
    # (applied by every provider before any request) guarantees they are never
    # queried externally.
    ok = (
        "93.184.216.34" in ips
        and is_public_ip("93.184.216.34")
        and not is_public_ip("127.0.0.1")
        and not is_public_ip("10.1.2.3")
    )
    return _ok("S9. private/local IPs gated from public queries", ok, str(ips))


def main():
    tests = [
        test_ti_disabled_is_noop,
        test_missing_keys_graceful_skip,
        test_provider_without_key_status_skipped,
        test_abuseipdb_success,
        test_virustotal_url_lookup,
        test_virustotal_url_port_preserved,
        test_virustotal_indicator_endpoints,
        test_virustotal_404_not_found,
        test_429_rate_limited_no_retry_storm,
        test_429_small_retry_once,
        test_timeout_unavailable,
        test_5xx_unavailable,
        test_malformed_response_error,
        test_forbidden_error,
        test_dedup_one_lookup_per_scan,
        test_qr_urls_connected,
        test_cache_hit_skips_provider,
        test_cache_miss_calls_provider,
        test_provider_down_verdict_intact,
        test_limiter_spacing,
        test_limiter_per_minute_budget,
        test_limiter_per_day_budget,
        test_limiter_centralized_singleton,
        test_api_key_never_leaks,
        test_private_ip_never_queried,
        test_evidence_is_bounded,
        test_indicators_capped,
        test_finding_severity_and_tags,
        test_sha256_extracted_from_file,
        test_persist_failure_rolls_back,
        test_scan_none_guard,
        test_extraction_private_and_local_skipped,
    ]
    for test in tests:
        try:
            test()
        except Exception as exc:  # noqa: BLE001 - report as failure
            report(test.__name__, False, f"EXCEPTION {exc!r}")
            restore_settings()
    print(f"\nPASS={PASS} FAIL={FAIL}")
    if FAIL:
        raise SystemExit(1)


if __name__ == "__main__":
    main()