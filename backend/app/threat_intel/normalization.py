"""Indicator normalization - deterministic, bounded, no network.

Rules:
- validate every indicator BEFORE anything is queried,
- only public/routable IPv4/IPv6 addresses are returned for IP queries,
- only http(s) URLs are accepted (deep links, local schemes, bare IP literals
  get classified as their primary indicator instead),
- domains are lowercase, trimmed of a single trailing root dot, no IDN
  unescaping, no subdomain magic: we query the exact extracted host.

No content is fetched or executed here; these helpers only shape strings.
"""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlsplit

_MAX_INDICATOR_LEN = 512

# Loose URL detector used by the extraction layer (mirrors analyzers/qr style).
_URL_RE = re.compile(r"\bhttps?://[^\s<>\"']+", re.IGNORECASE)

# Bounded domain shape: 1+ labels of [a-z0-9-] separated by dots, optional
# trailing root dot, at least one label + one dot.
_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.?$",
    re.IGNORECASE,
)

_SHA256_RE = re.compile(r"^[a-f0-9]{64}$", re.IGNORECASE)


def normalize_ip(raw: str) -> str | None:
    """Return the canonical string for a valid v4/v6 address, else None."""
    if raw is None:
        return None
    value = raw.strip()
    if not value or len(value) > 64:
        return None
    # Strip an optional IPv6 zone id ("fe80::1%eth0") - zone is link-local only.
    if "%" in value:
        value = value.split("%", 1)[0]
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        return None


def is_public_ip(raw: str) -> bool:
    """True only for routable public addresses (no private/local/reserved)."""
    canonical = normalize_ip(raw)
    if canonical is None:
        return False
    try:
        addr = ipaddress.ip_address(canonical)
    except ValueError:
        return False
    if addr.is_private or addr.is_loopback or addr.is_link_local:
        return False
    if addr.is_reserved or addr.is_multicast or addr.is_unspecified:
        return False
    return True


def normalize_domain(raw: str) -> str | None:
    """Return a lowercase hostname string, else None."""
    if raw is None:
        return None
    value = raw.strip().rstrip(".").lower()
    if not value or len(value) > 253:
        return None
    if not _DOMAIN_RE.match(value):
        return None
    return value


def normalize_url(raw: str) -> str | None:
    """Return a normalized http(s) URL, else None.

    The normalized form keeps scheme + host + port + path; fragment and
    query ordering are preserved verbatim (deterministic, no re-encoding).
    """
    if raw is None:
        return None
    value = raw.strip()
    if not value or len(value) > _MAX_INDICATOR_LEN:
        return None
    if not _URL_RE.match(value):
        return None
    # Align scheme/host case without touching the path.
    try:
        parts = urlsplit(value)
    except ValueError:
        return None
    scheme = (parts.scheme or "").lower()
    if scheme not in ("http", "https"):
        return None
    netloc = parts.netloc or ""
    host = netloc.rsplit("@", 1)[-1]
    if not host:
        return None
    host = host.lower()
    # Preserve any explicit port (host:8443, or an IPv4 literal host:port):
    # VirusTotal URL identifiers are the exact-string unpadded base64 of the
    # URL, so dropping the port would change the indicator and miss the report.
    normalized = f"{scheme}://{host}"
    if parts.path or parts.query or parts.fragment:
        normalized += parts.path or "/"
        if parts.query:
            normalized += "?" + parts.query
        if parts.fragment:
            normalized += "#" + parts.fragment
    return normalized[: _MAX_INDICATOR_LEN]


def classify_indicator(raw: str) -> tuple[str, str] | None:
    """Classify a candidate string into (indicator_type, normalized_value).

    Priority: IP literal -> URL -> domain -> None.
    A URL whose host is an IP literal is still classified as ``url`` (the host
    is queried separately as an IP when the extraction layer also finds it).
    Returns None for anything unrecognized or non-public/normalizable.
    """
    if raw is None:
        return None
    value = raw.strip()
    if not value or len(value) > _MAX_INDICATOR_LEN or any(c.isspace() for c in value):
        return None

    if normalize_ip(value) is not None:
        return ("ip", normalize_ip(value))
    url = normalize_url(value)
    if url is not None:
        return ("url", url)
    domain = normalize_domain(value)
    if domain is not None:
        return ("domain", domain)
    if _SHA256_RE.match(value):
        return ("sha256", value.lower())
    return None


def host_of_url(url: str) -> str | None:
    """Return the host/literal-IP of a normalized URL (bounded helper)."""
    if not url:
        return None
    try:
        parts = urlsplit(url)
    except ValueError:
        return None
    return parts.hostname.lower() if parts.hostname else None


def find_http_urls(text: str, limit: int = 50) -> list[str]:
    """Bounded http(s) URL scan of a text blob (QR payloads, evidence values)."""
    if not text:
        return []
    urls: list[str] = []
    for match in _URL_RE.findall(text)[:limit]:
        if len(match) > _MAX_INDICATOR_LEN:
            continue
        if match not in urls:
            urls.append(match)
    return urls