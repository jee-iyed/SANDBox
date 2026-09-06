"""Very cheap plain-text signature patterns for first-pass Fast Scan (M2).

These look at the raw bytes of the *sample* only. They are heuristic breadcrumbs,
NOT authoritative detection — deep/static analysis (M4) and YARA are authoritative.

Each signature: (name, bytes_pattern (as-is search), severity, tag).
"""

from app.db.models import Severity

# (name, pattern, severity)
_SIGS: list[tuple[str, bytes, Severity]] = [
    ("embedded_powershell", b"powershell", Severity.LOW),
    ("embedded_pwsh", b"pwsh", Severity.LOW),
    ("embedded_vba", b"VBA", Severity.LOW),
    ("embedded_macro", b"AutoOpen", Severity.LOW),
    ("embedded_js", b"<script", Severity.LOW),
    ("embedded_url", b"http://", Severity.INFO),
    ("embedded_urls", b"https://", Severity.INFO),
    ("embedded_registry_run", b"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", Severity.LOW),
    ("embedded_shell", b"/bin/sh", Severity.LOW),
]


def scan_sample(sample: bytes) -> list[tuple[str, bytes, Severity]]:
    """Return matched signatures (as high-level hits) found in the sample."""
    hits = []
    for name, pat, sev in _SIGS:
        idx = sample.find(pat)
        if idx != -1:
            hits.append((name, pat, sev))
    return hits
