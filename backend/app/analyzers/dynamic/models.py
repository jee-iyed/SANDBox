"""M5 Dynamic Analysis models: bounded, deterministic decision + result payload."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class DynamicDecision(str, Enum):
    """Explicit dynamic-analysis policy decision (observable, never silent)."""

    NOT_ELIGIBLE = "not_eligible"
    SKIPPED_BY_POLICY = "skipped_by_policy"
    EXECUTED = "executed"
    TIMEOUT = "timeout"
    EXECUTION_ERROR = "execution_error"
    SANDBOX_ERROR = "sandbox_error"


@dataclass
class DynamicAnalysisResult:
    """Bounded payload persisted via AnalysisResult.payload (no new DB model)."""

    decision: str
    reason: str
    status: str | None = None
    sandbox_id: str | None = None
    duration_ms: int = 0
    exit_code: int | None = None
    event_counts: dict = field(default_factory=dict)
    finding_counts: dict = field(default_factory=dict)
    policy: dict = field(default_factory=dict)
    error: str | None = None

    def to_dict(self) -> dict:
        return {
            "decision": self.decision,
            "reason": self.reason,
            "status": self.status,
            "sandbox_id": self.sandbox_id,
            "duration_ms": self.duration_ms,
            "exit_code": self.exit_code,
            "event_counts": {
                str(k)[:32]: int(v) for k, v in list(self.event_counts.items())[:16]
            },
            "finding_counts": {
                str(k)[:32]: int(v) for k, v in list(self.finding_counts.items())[:16]
            },
            "policy": self.policy,
            "error": (self.error or "")[:500] or None,
        }
