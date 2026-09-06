"""Static-analysis rule model + bounded matcher (M4).

A ``StaticRule`` declares *what to look for* in raw bytes, never *how to run* the
sample. Matching is purely lexical (byte substring + regex over a latin-1 view of
the bytes); it never executes anything, opens no network, and spawns no process.

The rule shape intentionally mirrors YARA's spirit (strings/patterns + metadata
+ severity), so a YARA backend can be introduced later behind the same
``match_rule`` contract without changing the analyzer or the finding schema.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from app.db.models import Severity

# Upper bound on the number of match entries we record per rule in evidence, so a
# pathological sample cannot bloat the persisted JSON.
MAX_EVIDENCE_MATCHES = 20


@dataclass(frozen=True)
class StaticRule:
    id: str
    name: str
    description: str
    category: str            # signature / command / script / url / encoding
    severity: Severity
    confidence: float
    byte_patterns: tuple[bytes, ...] = ()   # case-insensitive substring search
    regexes: tuple[str, ...] = ()           # regex over a latin-1 text view
    require_mixed: bool = False             # regex matches must mix upper+lower+digit
    tags: tuple[str, ...] = ()


def _has_mixed_charset(text: str) -> bool:
    """True if text contains at least one lowercase, one uppercase and one digit.

    Used to reject degenerate 'blob' matches like a long run of a single repeated
    char (e.g. padding), which is not a real encoded payload.
    """
    has_lower = has_upper = has_digit = False
    for ch in text:
        if "a" <= ch <= "z":
            has_lower = True
        elif "A" <= ch <= "Z":
            has_upper = True
        elif "0" <= ch <= "9":
            has_digit = True
        if has_lower and has_upper and has_digit:
            return True
    return False


def match_rule(rule: StaticRule, data: bytes) -> list[dict]:
    """Return the list of match evidence dicts for ``rule`` against ``data``.

    Evidence entries are small, JSON-serializable dicts. Byte patterns are matched
    case-insensitively; regexes run over a latin-1 decoding (1:1 byte mapping, so
    decoding never raises and offsets map back to byte offsets).
    """
    matches: list[dict] = []
    lowered = data.lower()
    for pat in rule.byte_patterns:
        needle = pat.lower()
        idx = lowered.find(needle)
        if idx != -1:
            matches.append(
                {
                    "kind": "bytes",
                    "pattern": pat.decode("latin-1", "replace"),
                    "offset": idx,
                }
            )

    if rule.regexes:
        text = data.decode("latin-1")
        for rgx in rule.regexes:
            compiled = re.compile(rgx, re.IGNORECASE | re.ASCII)
            for m in compiled.finditer(text):
                if len(matches) >= MAX_EVIDENCE_MATCHES:
                    break
                matched = m.group(0)
                if rule.require_mixed and not _has_mixed_charset(matched):
                    continue
                matches.append(
                    {
                        "kind": "regex",
                        "pattern": rgx,
                        "offset": m.start(),
                        "matched": matched[:200],
                    }
                )
    return matches[:MAX_EVIDENCE_MATCHES]
