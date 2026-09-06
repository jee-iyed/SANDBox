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
