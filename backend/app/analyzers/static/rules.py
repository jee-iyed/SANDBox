"""M4 static signature ruleset (declarative, no execution).

These rules answer: *does the file contain known suspicious/malicious static
patterns?* They operate on bytes only. None of them execute the sample, open
network, or spawn processes.

Design constraints (see DECISIONS.md D-10):
- Pure-Python, bounded, extensible. Not a huge malware database: a small, clearly
  defined POC set that a real signature DB / YARA can later extend.
- Distinct from M2's cheap heuristic breadcrumbs (fast_scan/signatures.py): M4
  rules are more specific/structured and carry higher severity + confidence, and
  always emit evidence.
- Every rule yields a normalized finding via ``source=static_analysis``.

Synthetic test markers are clearly labelled; no real malware is used anywhere.
"""

from app.analyzers.static.rule import StaticRule
from app.db.models import Severity

# Canonical EICAR test string (harmless industry-standard AV test signature).
EICAR = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"


RULES: list[StaticRule] = [
    # ------------------------------------------------------------------
    # Synthetic, deterministic test markers (documented; never real malware)
    # ------------------------------------------------------------------
    StaticRule(
        id="static_test_malware_marker",
        name="Synthetic test malware marker",
        description="Controlled synthetic marker for deterministic M4 tests.",
        category="signature",
        severity=Severity.CRITICAL,
        confidence=1.0,
        byte_patterns=(b"DOCSEC_M4_MALWARE_TEST_MARKER",),
        tags=("synthetic", "test"),
    ),
    StaticRule(
        id="static_eicar_signature",
        name="EICAR test file signature",
        description="Standard EICAR anti-virus test string (harmless).",
        category="signature",
        severity=Severity.LOW,
        confidence=0.95,
        byte_patterns=(EICAR,),
        tags=("test",),
    ),

    # ------------------------------------------------------------------
    # Suspicious command patterns
    # ------------------------------------------------------------------
    StaticRule(
        id="static_powershell_encoded",
        name="Encoded PowerShell command",
        description="PowerShell invoked with an encoded/obfuscated command.",
        category="command",
        severity=Severity.HIGH,
        confidence=0.85,
        byte_patterns=(
            b"powershell -enc",
            b"powershell -encodedcommand",
            b"powershell.exe -enc",
            b"powershell.exe -encodedcommand",
            b"pwsh -enc",
            b"pwsh -encodedcommand",
        ),
        tags=("powershell", "obfuscation"),
    ),
    StaticRule(
        id="static_suspicious_shell_command",
        name="Suspicious shell command invocation",
        description="Shell/scripting interpreter invoked with a command flag.",
        category="command",
        severity=Severity.HIGH,
        confidence=0.8,
        regexes=(
            r"\b(cmd\.exe|/bin/sh|/bin/bash|powershell(\.exe)?|pwsh|wscript(\.exe)?|cscript(\.exe)?)\s+[-/](c|e|enc)\b",
        ),
        tags=("shell", "command"),
    ),
    StaticRule(
        id="static_reverse_shell",
        name="Reverse shell / TCP payload indicator",
        description="Bash/dev-TCP reverse-shell or netcat -e backdoor idiom.",
        category="command",
        severity=Severity.HIGH,
        confidence=0.8,
        byte_patterns=(b"/dev/tcp/", b"/dev/udp/", b"nc -e ", b"netcat -e "),
        tags=("reverse_shell",),
    ),

    # ------------------------------------------------------------------
    # Script obfuscation indicators
    # ------------------------------------------------------------------
    StaticRule(
        id="static_obfuscated_script",
        name="Obfuscated script indicator",
        description="Char-code / unescape / eval-based script obfuscation.",
        category="script",
        severity=Severity.MEDIUM,
        confidence=0.7,
        regexes=(
            r"String\.fromCharCode",
            r"unescape\(%",
            r"eval\([^)]*unescape",
        ),
        tags=("javascript", "obfuscation"),
    ),
    StaticRule(
        id="static_activex_object",
        name="ActiveX / Windows scripting object",
        description="Creation of a Windows scripting/automation COM object.",
        category="script",
        severity=Severity.MEDIUM,
        confidence=0.75,
        byte_patterns=(b"WScript.Shell", b"Shell.Application", b"CreateObject("),
        tags=("activex", "script"),
    ),

    # ------------------------------------------------------------------
    # Suspicious URLs / IP literals
    # ------------------------------------------------------------------
    StaticRule(
        id="static_suspicious_url",
        name="Suspicious URL indicator",
        description="URL pointing at a commonly-abused free/throwaway TLD.",
        category="url",
        severity=Severity.MEDIUM,
        confidence=0.7,
        regexes=(
            r"https?://[^\s\"'<>]{0,80}\.(tk|cc|xyz|top|club|work|gq|ml|cf|ga)\b",
        ),
        tags=("url",),
    ),
    StaticRule(
        id="static_ipv4_literal",
        name="Embedded IPv4 literal",
        description="Literal IPv4 address embedded in the file.",
        category="url",
        severity=Severity.LOW,
        confidence=0.6,
        regexes=(r"\b(?:\d{1,3}\.){3}\d{1,3}\b",),
        tags=("network",),
    ),

    # ------------------------------------------------------------------
    # Encoded / obfuscated data blobs
    # ------------------------------------------------------------------
    StaticRule(
        id="static_base64_blob",
        name="Long base64 blob",
        description="Unusually long contiguous base64 run (mixed upper/lower/digit).",
        category="encoding",
        severity=Severity.LOW,
        confidence=0.6,
        regexes=(r"[A-Za-z0-9+/]{100,}={0,2}",),
        require_mixed=True,
        tags=("encoding", "base64"),
    ),
    StaticRule(
        id="static_hex_blob",
        name="Long hexadecimal blob",
        description="Unusually long contiguous hexadecimal run.",
        category="encoding",
        severity=Severity.LOW,
        confidence=0.5,
        regexes=(r"(?<![A-Fa-f0-9])[A-Fa-f0-9]{64,}(?![A-Fa-f0-9])",),
        tags=("encoding", "hex"),
    ),
]
