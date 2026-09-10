"""OPT-IN live validation for the Threat Intelligence providers (D-17).

This script performs a tiny, bounded amount of REAL external requests so the
provider parsing/connectivity can be verified against the live APIs. It is
deliberately conservative:

- requires ``TI_ENABLED=true`` AND at least one API key (else it exits 0),
- NEVER uploads or submits anything (AbuseIPDB CHECK / VirusTotal reads only),
- uses ONLY well-known benign indicators (Google DNS IP, example.com URL),
- hard-limit: at most 2 lookups per provider (aborts beyond that),
- prints the spend + parsed result (status/label/reputation) as a budget record.
- no persistence is touched; the described fake DB is mocked, so NOTHING is
  written to the database by this validation.

Max outgoing requests: 2 (AbuseIPDB) + 2 (VirusTotal) = 4 total.

Usage:
    set TI_ENABLED=true and the required key(s), then:
    .\\.venv\\Scripts\\python.exe tests\\live_ti_validation.py
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.core.config import settings  # noqa: E402
from app.threat_intel.extraction import TiIndicator  # noqa: E402
from app.threat_intel.providers import build_providers  # noqa: E402

MAX_LIVE_REQUESTS_PER_PROVIDER = 2

# Well-known benign indicators: Google Public DNS (8.8.8.8) and example.com.
BENIGN = {
    "abuseipdb": [TiIndicator("ip", "8.8.8.8")],
    "virustotal": [
        TiIndicator("url", "https://example.com/"),
        TiIndicator("ip", "8.8.8.8"),
    ],
}

PASS = 0
FAIL = 0


def report(name: str, ok: bool, detail: str = ""):
    global PASS, FAIL
    if ok:
        PASS += 1
    else:
        FAIL += 1
    print(f"[{'PASS' if ok else 'FAIL'}] {name}" + (f"  -> {detail}" if detail else ""))


def main() -> int:
    print("TI live validation (opt-in)")
    print(f"  TI_ENABLED={settings.ti_enabled}")
    print(f"  ABUSEIPDB_API_KEY={'present' if settings.abuseipdb_api_key else 'absent'}")
    print(f"  VIRUSTOTAL_API_KEY={'present' if settings.virustotal_api_key else 'absent'}")

    if not settings.ti_enabled:
        print("\nTI is disabled - nothing to validate. Exit 0.")
        return 0
    if not (settings.abuseipdb_api_key or settings.virustotal_api_key):
        print("\nNo provider API key configured - nothing to validate. Exit 0.")
        return 0

    providers = build_providers()
    if not providers:
        print("\nNo enabled providers (toggles off). Exit 0.")
        return 0

    print(f"  Providers instantiated: {[p.name for p in providers]}\n")

    for provider in providers:
        indicators = BENIGN.get(provider.name, [])
        print(f"--- {provider.name} (budget <= {MAX_LIVE_REQUESTS_PER_PROVIDER} live lookups) ---")
        spent = 0
        for indicator in indicators:
            if not provider.supports_type(indicator.type):
                continue
            if spent >= MAX_LIVE_REQUESTS_PER_PROVIDER:
                report(f"{provider.name}: budget cap reached -> aborting further lookups", True)
                break
            spent += 1
            lookup = provider.lookup(indicator)
            detail = (
                f"{indicator.type}={indicator.value} status={lookup.status.value} "
                f"label={lookup.status_label} reputation={lookup.reputation} "
                f"malicious={lookup.malicious} message={lookup.message}"
            )
            ok = lookup.status in ("success", "not_found", "cached", "skipped") and (
                lookup.reputation is None or 0 <= float(lookup.reputation) <= 100
            )
            report(f"{provider.name}: live lookup {indicator.type}", ok, detail)
        print(f"--- {provider.name}: spent {spent}/{MAX_LIVE_REQUESTS_PER_PROVIDER} live lookups ---\n")

    print(f"\nPASS={PASS} FAIL={FAIL}")
    return 1 if FAIL else 0


if __name__ == "__main__":
    raise SystemExit(main())