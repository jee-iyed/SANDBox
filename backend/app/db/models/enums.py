import enum


class ScanStatus(str, enum.Enum):
    QUEUED = "queued"
    PROCESSING = "processing"
    COMPLETED = "completed"
    FAILED = "failed"


class Verdict(str, enum.Enum):
    NOT_ANALYZED = "not_analyzed"
    SAFE = "safe"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"
    SANITIZED = "sanitized"


class Severity(str, enum.Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Action(str, enum.Enum):
    ALLOW = "allow"
    QUARANTINE = "quarantine"
    SANITIZE = "sanitize"
    REJECT = "reject"


class AnalysisStatus(str, enum.Enum):
    OK = "ok"
    ERROR = "error"
    SKIPPED = "skipped"


class SecureAccessStatus(str, enum.Enum):
    """Secure File Access state machine (see DECISIONS.md D-16).

    Bounded, deterministic, fail-closed. An access is only ever AUTHORIZED
    when the underlying scan completed with an allowed verdict AND the access
    has not expired. Every other path (unknown, running, failed, expired or a
    suspicious/malicious verdict) resolves to a non-authorized state.
    """

    REQUESTED = "requested"
    SCANNING = "scanning"
    AUTHORIZED = "authorized"
    BLOCKED = "blocked"
    QUARANTINED = "quarantined"
    FAILED = "failed"
    EXPIRED = "expired"
