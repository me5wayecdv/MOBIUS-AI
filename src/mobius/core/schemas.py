"""Domain models.

These are the contracts every layer speaks. They are Pydantic models rather than ORM
entities so the domain core can be tested with no database, and so the same schema
generates the JSON Schema handed to a model (docs/MODEL_ROUTING.md 3).

Three invariants are enforced *in the model*, not in a service, because they are the
difference between an investigator and a scanner:

1. A ``fact`` carries evidence and has confidence exactly 1.0. Anything less is an
   ``inference`` (ADR-005).
2. Severity, confidence and status are independent. There is no ``risk_score`` property
   and no averaging anywhere.
3. A confirmed finding names its validator and carries evidence.

If these were only conventions in prose, they would erode under deadline pressure. Here
they raise.
"""

from __future__ import annotations

from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from .enums import (
    ApprovalState,
    AssertionLevel,
    EvidenceKind,
    Fidelity,
    FindingStatus,
    HypothesisStatus,
    InvestigationState,
    ObservationKind,
    RejectionReason,
    Severity,
    StopReason,
    ToolStatus,
    Verdict,
)
from .ids import IdPrefix, new_id

# ULID pattern per docs/API_SPECIFICATION.md 1: Crockford base32, 26 chars.
_ULID = r"[0-9A-HJKMNP-TV-Z]{26}"
Confidence = Annotated[float, Field(ge=0.0, le=1.0)]
IntensityLevel = Annotated[int, Field(ge=0, le=3)]


class _Model(BaseModel):
    # extra="forbid" everywhere: silently ignoring a misspelled field like "intesity"
    # is a security bug in a tool whose configuration gates sandbox policy.
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


# --------------------------------------------------------------------------------------
# Safe PoC / TestPlan (D-040)
# --------------------------------------------------------------------------------------


class PoCStep(_Model):
    """One closed-registry action; plans cannot provide shell commands or arbitrary URLs."""

    action: Literal[
        "assert_manifest_component",
        "assert_manifest_permission",
        "invoke_local_harness",
        "assert_local_harness_result",
        "assert_emulator_package_present",
        "assert_emulator_provider_rows",
        "assert_emulator_frida_classes",
        "capture_native_local_fixture_v1",
    ]
    target_ref: str = Field(min_length=1, max_length=500)
    expected_value: str | bool | int | None = None
    input_values: dict[str, str | bool | int] = Field(default_factory=dict, max_length=12)
    timeout_seconds: int = Field(default=15, ge=1, le=60)

    @model_validator(mode="after")
    def _closed_harness_inputs(self) -> PoCStep:
        if self.action == "invoke_local_harness":
            if set(self.input_values) - {"url"}:
                raise ValueError("local harness accepts only the bounded url input")
            url = self.input_values.get("url")
            if url is not None and (not isinstance(url, str) or len(url) > 2048):
                raise ValueError("local harness url input must be a string of at most 2048 chars")
        elif self.input_values:
            raise ValueError("input_values are allowed only for invoke_local_harness")
        if self.action == "assert_local_harness_result" and self.target_ref not in {
            "sink_invoked", "blocked", "scheme", "forwarded_url", "source", "simulation"
        }:
            raise ValueError("local harness result key is not allowlisted")
        if self.action == "assert_emulator_package_present":
            if not isinstance(self.expected_value, bool):
                raise ValueError("emulator package presence expects a boolean expected_value")
        if self.action in {"assert_emulator_provider_rows", "assert_emulator_frida_classes"}:
            # Threshold semantics: pass when at least expected_value rows
            # (or enumerated classes) are observed.
            if not isinstance(self.expected_value, int) or isinstance(self.expected_value, bool) \
                    or self.expected_value < 0:
                raise ValueError("emulator threshold probes expect a non-negative integer expected_value")
        return self


class PoCCleanupStep(_Model):
    action: Literal["remove_temporary_workspace", "reset_local_harness", "stop_emulator_instrumentation", "stop_native_local_fixture"]
    target_ref: str = Field(min_length=1, max_length=300)
    timeout_seconds: int = Field(default=15, ge=1, le=60)


class PoCTestPlan(_Model):
    """Typed, scoped, budgeted plan for a non-destructive lab proof."""

    id: str = Field(
        default_factory=lambda: new_id(IdPrefix.POC_PLAN),
        pattern=rf"^poc_{_ULID}$",
    )
    investigation_id: str = Field(min_length=1)
    authorization_id: str = Field(min_length=1)
    target_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    target_package: str = Field(min_length=1, max_length=255)
    target_kind: Literal["lab_apk", "local_harness", "emulator", "native_local_fixture"]
    hypothesis_ids: tuple[str, ...] = Field(min_length=1, max_length=20)
    prerequisites: tuple[str, ...] = Field(default=(), max_length=30)
    steps: tuple[PoCStep, ...] = Field(min_length=1, max_length=20)
    expected_outcome: str = Field(min_length=1, max_length=2000)
    safety_class: Literal["read_only", "non_destructive", "state_changing"] = "read_only"
    max_duration_seconds: int = Field(default=60, ge=1, le=300)
    max_output_bytes: int = Field(default=65536, ge=1, le=1_048_576)
    cleanup_steps: tuple[PoCCleanupStep, ...] = Field(default=(), max_length=10)
    requires_approval: bool = False
    approval_id: str | None = Field(default=None, min_length=1, max_length=40)

    @model_validator(mode="after")
    def _bounded_and_approved(self) -> PoCTestPlan:
        if self.target_kind == "native_local_fixture":
            if (self.safety_class != "non_destructive" or not self.requires_approval
                or len(self.steps) != 1
                or self.steps[0].action != "capture_native_local_fixture_v1"
                or self.steps[0].target_ref != "trusted-local-positive-v1"
                or self.steps[0].expected_value is not None
                or self.steps[0].input_values
                or len(self.cleanup_steps) != 1
                or self.cleanup_steps[0].action != "stop_native_local_fixture"
                or self.cleanup_steps[0].target_ref != "trusted-local-positive-v1"):
                raise ValueError("native local fixture requires its fixed approved profile/action/cleanup")
            if self.steps[0].timeout_seconds+self.cleanup_steps[0].timeout_seconds>self.max_duration_seconds:
                raise ValueError("native operation plus teardown budgets exceed approved duration")
        elif any(s.action == "capture_native_local_fixture_v1" for s in self.steps) or any(
            c.action == "stop_native_local_fixture" for c in self.cleanup_steps
        ):
            raise ValueError("native fixture actions require the explicit native_local_fixture target")
        total_timeout = sum(step.timeout_seconds for step in self.steps)
        if total_timeout > self.max_duration_seconds:
            raise ValueError("sum of step timeouts exceeds max_duration_seconds")
        if self.safety_class != "read_only" and not self.requires_approval:
            raise ValueError("non-read-only PoC plans require explicit approval")
        if self.requires_approval and self.approval_id is not None and not self.approval_id.startswith("apr_"):
            raise ValueError("approval_id must be an approval record ID")
        if self.safety_class != "read_only" and not self.cleanup_steps:
            raise ValueError("non-read-only PoC plans must define cleanup_steps")
        if self.target_kind == "local_harness" and any(
            step.action in {"assert_manifest_component", "assert_manifest_permission"}
            for step in self.steps
        ):
            raise ValueError("manifest assertions require a lab_apk or emulator target")
        if any(
            step.action in {"assert_emulator_package_present", "assert_emulator_provider_rows",
                            "assert_emulator_frida_classes"}
            for step in self.steps
        ) and self.target_kind != "emulator":
            raise ValueError("emulator probes require an emulator target")
        if any(step.action == "assert_emulator_frida_classes" for step in self.steps) \
                and self.safety_class != "non_destructive":
            # Instrumentation attaches to a running process: more than
            # read_only, so it flows through the existing approval gate via
            # the non_destructive class (which requires approval + cleanup).
            raise ValueError("frida instrumentation probes require the non_destructive safety class")
        return self


# --------------------------------------------------------------------------------------
# Evidence
# --------------------------------------------------------------------------------------


class Evidence(_Model):
    """An immutable, content-addressed artefact.

    Identity is the SHA-256 of the bytes, so the same manifest extracted twice does not
    produce two evidence rows. Corrections are new evidence plus a superseding
    reference - never an edit (ADR-009).
    """

    id: str = Field(default_factory=lambda: new_id(IdPrefix.EVIDENCE), pattern=rf"^ev_{_ULID}$")
    investigation_id: str
    kind: EvidenceKind
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    object_key: str
    byte_size: int = Field(ge=0)
    truncated: bool = False
    redacted: bool = False
    summary: str = Field(min_length=1, max_length=2000)
    produced_by: str = Field(min_length=1)


# --------------------------------------------------------------------------------------
# Observation / hypothesis / decision - three separate entities (ADR-005)
# --------------------------------------------------------------------------------------


class Observation(_Model):
    """A typed, evidence-backed statement about the artefact under investigation."""

    id: str = Field(default_factory=lambda: new_id(IdPrefix.OBSERVATION), pattern=rf"^obs_{_ULID}$")
    investigation_id: str
    agent: str = Field(min_length=1)
    kind: ObservationKind
    fidelity: Fidelity
    subject_type: str | None = None
    subject_ref: str | None = None
    statement: str = Field(min_length=1)
    attributes: dict[str, Any] = Field(default_factory=dict)
    maswe: tuple[str, ...] = ()
    confidence: Confidence = 1.0
    evidence_refs: tuple[str, ...] = ()

    @model_validator(mode="after")
    def _fact_is_evidenced_and_certain(self) -> Observation:
        if self.kind is ObservationKind.FACT:
            if not self.evidence_refs:
                raise ValueError(
                    "an observation of kind 'fact' must cite at least one evidence_ref "
                    "(a claim without evidence is an inference, not a fact)"
                )
            if self.confidence != 1.0:
                raise ValueError(
                    "an observation of kind 'fact' must have confidence 1.0; "
                    f"got {self.confidence}. Use kind='inference' instead."
                )
        return self


class Hypothesis(_Model):
    """A testable security claim awaiting evidence.

    ``required_evidence`` is declared *before* testing so the goalposts cannot move after
    an agent has looked. ``satisfied_evidence`` is filled only by the gate evaluator.
    """

    id: str = Field(default_factory=lambda: new_id(IdPrefix.HYPOTHESIS), pattern=rf"^hyp_{_ULID}$")
    investigation_id: str
    claim: str = Field(min_length=10)
    maswe: tuple[str, ...] = ()
    derived_from: tuple[str, ...] = ()
    required_evidence: tuple[str, ...] = ()
    satisfied_evidence: tuple[str, ...] = ()
    status: HypothesisStatus = HypothesisStatus.OPEN
    priority: Annotated[float, Field(ge=0.0, le=1.0)] = 0.5
    depth: int = Field(default=0, ge=0)
    parent_id: str | None = None

    @model_validator(mode="after")
    def _satisfied_is_a_subset(self) -> Hypothesis:
        unknown = set(self.satisfied_evidence) - set(self.required_evidence)
        if unknown:
            raise ValueError(
                "satisfied_evidence must be a subset of required_evidence; "
                f"undeclared clauses: {sorted(unknown)}"
            )
        return self

    @property
    def is_satisfied(self) -> bool:
        return bool(self.required_evidence) and set(self.required_evidence) <= set(
            self.satisfied_evidence
        )


class RejectedAlternative(_Model):
    action: str
    target: str | None = None
    reason: str = Field(min_length=1)


class Decision(_Model):
    """Why the system did what it did. Auditable, and deliberately NOT chain-of-thought.

    The audit trail is the action, its inputs, its evidence and its expected outcome -
    things that are checkable. A narrative is not.
    """

    id: str = Field(default_factory=lambda: new_id(IdPrefix.DECISION), pattern=rf"^dec_{_ULID}$")
    investigation_id: str
    agent: str
    action: str
    action_args: dict[str, Any] = Field(default_factory=dict)
    considered_evidence: tuple[str, ...] = ()
    alternatives_rejected: tuple[RejectedAlternative, ...] = ()
    expected_outcome: str = Field(min_length=1)
    uncertainty: str | None = None
    prompt_version: str | None = None
    model_id: str | None = None

    @model_validator(mode="after")
    def _alternatives_must_be_justified(self) -> Decision:
        # Choosing between options without recording why the others lost is how an
        # investigation becomes unreviewable.
        for alt in self.alternatives_rejected:
            if not alt.reason.strip():
                raise ValueError("a rejected alternative must state a reason")
        return self


# --------------------------------------------------------------------------------------
# Findings and verdicts
# --------------------------------------------------------------------------------------


class SourceRef(_Model):
    file: str
    class_name: str | None = Field(default=None, alias="class")
    method: str | None = None
    lines: tuple[int, int] | None = None

    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    @model_validator(mode="after")
    def _lines_ordered(self) -> SourceRef:
        if self.lines and self.lines[0] > self.lines[1]:
            raise ValueError("source_ref.lines must be (start, end) with start <= end")
        return self


class Finding(_Model):
    """An asserted, validated claim. Severity and confidence are independent columns."""

    id: str = Field(default_factory=lambda: new_id(IdPrefix.FINDING), pattern=rf"^fnd_{_ULID}$")
    investigation_id: str
    title: str = Field(min_length=5)
    category: str = Field(min_length=1)
    description: str = Field(min_length=1)
    component_ref: str | None = None
    source_ref: SourceRef | None = None
    evidence_refs: tuple[str, ...] = ()
    masvs: tuple[str, ...] = ()
    maswe: tuple[str, ...] = ()
    mastg: tuple[str, ...] = ()
    severity: Severity
    severity_vector: str | None = None
    confidence: Confidence
    status: FindingStatus = FindingStatus.DISCOVERED
    discovered_by: str
    validated_by: str | None = None
    gate_evidence: dict[str, bool | None] = Field(default_factory=dict)
    remediation: str | None = None

    @model_validator(mode="after")
    def _confirmation_is_supported(self) -> Finding:
        if self.status is FindingStatus.CONFIRMED:
            if not self.validated_by:
                raise ValueError("a confirmed finding must name its validator (validated_by)")
            if not self.evidence_refs:
                raise ValueError("a confirmed finding must carry evidence_refs")
            if not self.gate_evidence:
                raise ValueError(
                    "a confirmed finding must record gate_evidence showing which clauses passed"
                )
            # `None` means a clause was never established; only `True` counts as satisfied.
            if not all(value is True for value in self.gate_evidence.values()):
                raise ValueError(
                    "every gate clause must have passed for a finding to be confirmed; "
                    f"failed clauses: {sorted(k for k, v in self.gate_evidence.items() if not v)}"
                )
            if self.validated_by == self.discovered_by:
                raise ValueError(
                    "the validator must differ from the discoverer (ADR-010): "
                    f"both are {self.discovered_by!r}"
                )
        return self


class VerdictRecord(_Model):
    """An independent validation outcome. Four-valued by design."""

    id: str = Field(default_factory=lambda: new_id(IdPrefix.VERDICT), pattern=rf"^vrd_{_ULID}$")
    finding_id: str
    verdict: Verdict
    rejection_reason: RejectionReason | None = None
    rationale: str = Field(min_length=1)
    gate_passed: bool
    gate_detail: dict[str, bool | None] = Field(default_factory=dict)
    validated_by: str
    model_id: str | None = None

    @model_validator(mode="after")
    def _rejection_states_why(self) -> VerdictRecord:
        if self.verdict is Verdict.REJECTED and self.rejection_reason is None:
            raise ValueError("a rejected verdict must state a rejection_reason")
        if self.verdict is Verdict.CONFIRMED and not self.gate_passed:
            raise ValueError("a confirmed verdict requires gate_passed=True")
        return self


# --------------------------------------------------------------------------------------
# Authorisation, application, investigation
# --------------------------------------------------------------------------------------


class Authorization(_Model):
    """The control that makes the project defensible. Bound to the APK hash, not the name."""

    id: str = Field(
        default_factory=lambda: new_id(IdPrefix.AUTHORIZATION), pattern=rf"^ath_{_ULID}$"
    )
    target_package: str = Field(min_length=1)
    apk_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    scope_text: str = Field(min_length=20, max_length=4000)
    max_intensity: IntensityLevel
    statement: str = Field(min_length=1)
    granted_by: str
    expires_at: str
    revoked_at: str | None = None

    @property
    def is_live(self) -> bool:
        return self.revoked_at is None


class Application(_Model):
    id: str = Field(default_factory=lambda: new_id(IdPrefix.APPLICATION), pattern=rf"^app_{_ULID}$")
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    package_name: str | None = None
    version_name: str | None = None
    version_code: int | None = None
    min_sdk: int | None = None
    target_sdk: int | None = None
    file_size: int = Field(ge=0)
    artifact_key: str


class Budget(_Model):
    max_steps: int = Field(default=60, ge=1)
    max_model_tokens: int = Field(default=400_000, ge=0)
    max_tool_calls: int = Field(default=80, ge=0)
    max_wall_seconds: int = Field(default=1800, ge=1)


class BudgetUsage(_Model):
    steps: int = 0
    model_tokens: int = 0
    tool_calls: int = 0
    wall_seconds: int = 0

    def exceeded(self, budget: Budget) -> str | None:
        """Return the first exhausted resource name, or None. Budget is a hard ceiling."""
        checks = (
            ("steps", budget.max_steps),
            ("model_tokens", budget.max_model_tokens),
            ("tool_calls", budget.max_tool_calls),
            ("wall_seconds", budget.max_wall_seconds),
        )
        for name, limit in checks:
            if getattr(self, name) >= limit:
                return name
        return None


class LLMSharing(_Model):
    """Off by default. Sending decompiled proprietary code to a third party is a decision
    an operator makes explicitly, per scan (docs/THREAT_MODEL.md B6)."""

    enabled: bool = False
    provider: str | None = None


class Investigation(_Model):
    id: str = Field(
        default_factory=lambda: new_id(IdPrefix.INVESTIGATION), pattern=rf"^scn_{_ULID}$"
    )
    application_id: str
    authorization_id: str | None = None
    created_by: str
    objective: str = Field(min_length=10, max_length=2000)
    intensity: IntensityLevel = 0
    state: InvestigationState = InvestigationState.INTAKE
    budget: Budget = Field(default_factory=Budget)
    used: BudgetUsage = Field(default_factory=BudgetUsage)
    llm_data_sharing: LLMSharing = Field(default_factory=LLMSharing)
    # Pause is a flag, not a state (ADR-017).
    paused_at: str | None = None
    paused_by: str | None = None
    pause_reason: str | None = None
    stop_reason: StopReason | None = None

    @model_validator(mode="after")
    def _pause_is_coherent(self) -> Investigation:
        if (self.paused_at is None) != (self.paused_by is None):
            raise ValueError("paused_at and paused_by must be set together")
        return self

    @property
    def is_paused(self) -> bool:
        return self.paused_at is not None


# --------------------------------------------------------------------------------------
# Frontier and tool execution
# --------------------------------------------------------------------------------------


class FrontierEntry(_Model):
    """One candidate action on the investigation worklist."""

    id: str = Field(default_factory=lambda: new_id(IdPrefix.FRONTIER), pattern=rf"^fro_{_ULID}$")
    investigation_id: str
    action: str
    action_args: dict[str, Any] = Field(default_factory=dict)
    required_agent: str
    relates_to_maswe: tuple[str, ...] = ()
    #: Scoring metadata for gate-seeded entries: when set, impact comes from the
    #: category's preserved weight, not from resolving relates_to_maswe. Decoupled
    #: from the taxonomy IDs on purpose so metadata corrections cannot move scores.
    gate_category: str | None = None
    score: float = 0.0
    depth: int = Field(default=0, ge=0)
    state: Literal["queued", "leased", "done", "dropped", "failed"] = "queued"
    attempts: int = Field(default=0, ge=0)


class ToolExecution(_Model):
    id: str
    investigation_id: str
    tool: str
    tool_version: str
    argv: tuple[str, ...] = ()
    status: ToolStatus
    exit_code: int | None = None
    duration_ms: int = Field(ge=0)
    stderr_tail: str | None = None


class Approval(_Model):
    """A bounded, expiring grant to act above the authorisation's blanket intensity."""

    id: str = Field(default_factory=lambda: new_id(IdPrefix.APPROVAL), pattern=rf"^apr_{_ULID}$")
    investigation_id: str
    requested_action: str = Field(min_length=1)
    intensity_required: IntensityLevel
    intensity_granted: IntensityLevel | None = None
    justification: str = Field(min_length=10)
    risk_summary: str = Field(min_length=1)
    state: ApprovalState = ApprovalState.PENDING
    requested_by: str
    decided_by: str | None = None
    decision_note: str | None = None
    expires_at: str

    @model_validator(mode="after")
    def _grant_is_bounded(self) -> Approval:
        if self.state is ApprovalState.REJECTED and self.intensity_granted is not None:
            raise ValueError("a rejected approval grants nothing")
        if (
            self.intensity_granted is not None
            and self.intensity_granted > self.intensity_required
        ):
            raise ValueError("a grant may narrow the request, never widen it")
        if self.state not in (ApprovalState.PENDING, ApprovalState.EXPIRED) and not self.decided_by:
            raise ValueError("a decided approval must name decided_by")
        return self


# --------------------------------------------------------------------------------------
# Attack graph
# --------------------------------------------------------------------------------------


class GraphNode(_Model):
    id: str = Field(default_factory=lambda: new_id(IdPrefix.GRAPH_NODE), pattern=rf"^gph_{_ULID}$")
    investigation_id: str
    node_type: str
    label: str
    ref: str | None = None
    assertion: AssertionLevel
    attributes: dict[str, Any] = Field(default_factory=dict)
    evidence_refs: tuple[str, ...] = ()


class GraphEdge(_Model):
    id: str = Field(default_factory=lambda: new_id(IdPrefix.GRAPH_EDGE), pattern=rf"^ged_{_ULID}$")
    investigation_id: str
    source_id: str
    target_id: str
    relation: str
    assertion: AssertionLevel
    rationale: str | None = None
    evidence_refs: tuple[str, ...] = ()

    @model_validator(mode="after")
    def _hypothesis_states_why(self) -> GraphEdge:
        # AC-FR-GRAPH-2: a hypothetical relationship must say why it is hypothesised,
        # so the UI can never render a guess as a fact.
        if self.assertion is AssertionLevel.HYPOTHESIS and not (self.rationale or "").strip():
            raise ValueError("a hypothesised edge must carry a rationale")
        return self
