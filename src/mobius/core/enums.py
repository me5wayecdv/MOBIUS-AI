"""Closed vocabularies.

Every one of these is a *closed* set on purpose. In docs/AGENT_DESIGN.md 3 the rule is
that a free-text field which should be an enum is where hallucination enters: a model
with no legal way to say "insufficient evidence" will guess. Encoding the vocabularies
here means a model cannot invent a verdict, a fidelity or a state.
"""

from __future__ import annotations

from enum import StrEnum


class InvestigationState(StrEnum):
    """The 15 FSM states. Pause is a flag, not one of these - see ADR-017."""

    INTAKE = "INTAKE"
    SCOPE_BLOCKED = "SCOPE_BLOCKED"
    RECON = "RECON"
    SURFACE_READY = "SURFACE_READY"
    SELECTING = "SELECTING"
    DISPATCHING = "DISPATCHING"
    OBSERVING = "OBSERVING"
    VALIDATING = "VALIDATING"
    AWAITING_APPROVAL = "AWAITING_APPROVAL"
    CORRELATING = "CORRELATING"
    REPORTING = "REPORTING"
    CLOSED = "CLOSED"
    BUDGET_EXHAUSTED = "BUDGET_EXHAUSTED"
    CANCELLED = "CANCELLED"
    FAILED = "FAILED"


class StopReason(StrEnum):
    COMPLETED = "completed"
    BUDGET_EXHAUSTED = "budget_exhausted"
    CANCELLED = "cancelled"
    ERROR = "error"


class Fidelity(StrEnum):
    """How much to trust the artefact a claim was read from.

    ``decompiler-failed`` is a first-class value: JADX failing on a method is information,
    not an error to hide (docs/ANDROID_SECURITY_METHODOLOGY.md 5).
    """

    BINARY_XML = "binary-xml"
    DECOMPILED = "decompiled"
    SMALI = "smali"
    DECOMPILER_FAILED = "decompiler-failed"
    RUNTIME = "runtime"
    CONFIG = "config"


class ObservationKind(StrEnum):
    FACT = "fact"          # confidence must be 1.0 and evidence_refs non-empty
    INFERENCE = "inference"
    ANOMALY = "anomaly"


class HypothesisStatus(StrEnum):
    OPEN = "open"
    TESTING = "testing"
    SUPPORTED = "supported"
    REFUTED = "refuted"
    ABANDONED = "abandoned"
    PARKED = "parked"


class EvidenceKind(StrEnum):
    MANIFEST = "manifest"
    SOURCE = "source"
    SMALI = "smali"
    DEX_STRING = "dex-string"
    TOOL_OUTPUT = "tool-output"
    HTTP = "http"
    LOGCAT = "logcat"
    CONFIG = "config"
    CERTIFICATE = "certificate"
    SCREENSHOT = "screenshot"
    REPORT = "report"
    POC_PLAN = "poc-plan"
    POC_RESULT = "poc-result"
    POC_LOG = "poc-log"


class Severity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class FindingStatus(StrEnum):
    """The seven-state lifecycle from the project brief 8."""

    DISCOVERED = "discovered"
    UNDER_INVESTIGATION = "under_investigation"
    POTENTIAL = "potential"
    AWAITING_VALIDATION = "awaiting_validation"
    CONFIRMED = "confirmed"
    REJECTED = "rejected"
    MANUAL_REVIEW_REQUIRED = "manual_review_required"


class Verdict(StrEnum):
    """Four-valued on purpose. Forcing a binary verdict manufactures false certainty."""

    CONFIRMED = "confirmed"
    REJECTED = "rejected"
    NEEDS_MANUAL_REVIEW = "needs_manual_review"
    INSUFFICIENT_EVIDENCE = "insufficient_evidence"


class RejectionReason(StrEnum):
    NOT_REACHABLE = "not-reachable"
    GUARDED_BY_CALLER_CHECK = "guarded-by-caller-check"
    SANITISED = "sanitised"
    MITIGATED_BY_PLATFORM = "mitigated-by-platform"
    MISREAD_CODE = "misread-code"
    NOT_SENSITIVE_DATA = "not-sensitive-data"
    TEST_ONLY_VALUE = "test-only-value"


class AssertionLevel(StrEnum):
    """How strongly an edge or node in the attack graph is asserted.

    Ordering matters: a confirmed claim outranks an observation, which outranks a
    hypothesis. Path queries filter by a minimum level (FR-GRAPH-4).
    """

    REJECTED = "rejected"
    HYPOTHESIS = "hypothesis"
    OBSERVED = "observed"
    CONFIRMED = "confirmed"

    @property
    def rank(self) -> int:
        return _ASSERTION_RANK[self]


_ASSERTION_RANK = {
    AssertionLevel.REJECTED: 0,
    AssertionLevel.HYPOTHESIS: 1,
    AssertionLevel.OBSERVED: 2,
    AssertionLevel.CONFIRMED: 3,
}


class ToolStatus(StrEnum):
    OK = "ok"
    ERROR = "error"
    TIMEOUT = "timeout"
    UNAVAILABLE = "unavailable"
    KILLED = "killed"


class ApprovalState(StrEnum):
    PENDING = "pending"
    GRANTED = "granted"
    REJECTED = "rejected"
    EXPIRED = "expired"
    REVOKED = "revoked"


class Intensity:
    """Test-intensity levels. Higher numbers authorise more invasive testing.

    Intensity is checked in three places, deliberately: the API (fast, friendly error),
    the IntakeService (domain rule) and a database trigger (backstop that cannot be
    bypassed). See docs/DATABASE_SCHEMA.md and ADR-016.
    """

    PASSIVE = 0        # static analysis only; nothing is executed
    OBSERVATIONAL = 1  # launch and observe
    INTERACTIONAL = 2  # approved intents, approved input, isolated network
    DESTRUCTIVE = 3    # disabled in v1

    ALL = frozenset({0, 1, 2, 3})
    MAX_ENABLED = 2  # intensity 3 exists in the model but is refused by policy
