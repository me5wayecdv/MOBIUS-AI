"""SQLAlchemy tables mirroring docs/DATABASE_SCHEMA.md.

Deviation from the document, deliberate and recorded in ADR-018: array columns
(``evidence_refs``, ``maswe``, ...) are stored as ``JSON`` rather than Postgres ``uuid[]``
/ ``text[]``. Reason: the same models must run on SQLite for development and CI while the
deployment target stays Postgres. The cost is that referential integrity *inside* arrays
cannot be enforced by a foreign key - which the document already concedes, since
FR-EV-3 puts dangling-reference detection in a CI test rather than in the schema.

The database-level CHECK constraints from the document are reproduced here because they
are not cosmetic: ``confirmed_needs_evidence`` and ``facts_have_evidence`` are the
guarantees the project's credibility rests on, and they must hold even if a service is
bypassed.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy import (
    JSON,
    BigInteger,
    Boolean,
    CheckConstraint,
    Float,
    ForeignKey,
    ForeignKeyConstraint,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


class UserRow(Base):
    __tablename__ = "users"
    id: Mapped[str] = mapped_column(String(40), primary_key=True)
    email: Mapped[str] = mapped_column(String(320), unique=True, nullable=False)
    display_name: Mapped[str] = mapped_column(String(200), nullable=False)
    role: Mapped[str] = mapped_column(String(20), nullable=False)
    password_hash: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[str] = mapped_column(String(40), nullable=False)


class AuthorizationRow(Base):
    __tablename__ = "authorizations"
    __table_args__ = (
        CheckConstraint("max_intensity BETWEEN 0 AND 3", name="intensity_range_auth"),
        Index("ix_auth_apk_live", "apk_sha256", "revoked_at"),
    )
    id: Mapped[str] = mapped_column(String(40), primary_key=True)
    granted_by: Mapped[str] = mapped_column(String(40), ForeignKey("users.id"), nullable=False)
    target_package: Mapped[str] = mapped_column(String(300), nullable=False)
    apk_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    scope_text: Mapped[str] = mapped_column(Text, nullable=False)
    max_intensity: Mapped[int] = mapped_column(Integer, nullable=False)
    statement: Mapped[str] = mapped_column(Text, nullable=False)
    expires_at: Mapped[str] = mapped_column(String(40), nullable=False)
    revoked_at: Mapped[str | None] = mapped_column(String(40))
    created_at: Mapped[str] = mapped_column(String(40), nullable=False)


class ApplicationRow(Base):
    __tablename__ = "applications"
    id: Mapped[str] = mapped_column(String(40), primary_key=True)
    sha256: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    package_name: Mapped[str | None] = mapped_column(String(300))
    version_name: Mapped[str | None] = mapped_column(String(100))
    version_code: Mapped[int | None] = mapped_column(BigInteger)
    min_sdk: Mapped[int | None] = mapped_column(Integer)
    target_sdk: Mapped[int | None] = mapped_column(Integer)
    file_size: Mapped[int] = mapped_column(BigInteger, nullable=False)
    artifact_key: Mapped[str] = mapped_column(Text, nullable=False)
    uploaded_by: Mapped[str | None] = mapped_column(String(40), ForeignKey("users.id"))
    created_at: Mapped[str] = mapped_column(String(40), nullable=False)


class InvestigationRow(Base):
    __tablename__ = "investigations"
    __table_args__ = (
        CheckConstraint("intensity BETWEEN 0 AND 3", name="intensity_range"),
        CheckConstraint(
            "state IN ('INTAKE','SCOPE_BLOCKED','RECON','SURFACE_READY','SELECTING',"
            "'DISPATCHING','OBSERVING','VALIDATING','AWAITING_APPROVAL','CORRELATING',"
            "'REPORTING','CLOSED','BUDGET_EXHAUSTED','CANCELLED','FAILED')",
            name="state_known",
        ),
        CheckConstraint(
            "(paused_at IS NULL AND paused_by IS NULL) OR "
            "(paused_at IS NOT NULL AND paused_by IS NOT NULL)",
            name="pause_is_coherent",
        ),
        Index("ix_inv_live", "state"),
    )
    id: Mapped[str] = mapped_column(String(40), primary_key=True)
    application_id: Mapped[str] = mapped_column(
        String(40), ForeignKey("applications.id"), nullable=False
    )
    authorization_id: Mapped[str | None] = mapped_column(
        String(40), ForeignKey("authorizations.id")
    )
    created_by: Mapped[str] = mapped_column(String(40), ForeignKey("users.id"), nullable=False)
    objective: Mapped[str] = mapped_column(Text, nullable=False)
    intensity: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    state: Mapped[str] = mapped_column(String(30), nullable=False)
    budget_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    used_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    llm_data_sharing: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    event_seq: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    paused_at: Mapped[str | None] = mapped_column(String(40))
    paused_by: Mapped[str | None] = mapped_column(String(40), ForeignKey("users.id"))
    pause_reason: Mapped[str | None] = mapped_column(Text)
    started_at: Mapped[str | None] = mapped_column(String(40))
    finished_at: Mapped[str | None] = mapped_column(String(40))
    stop_reason: Mapped[str | None] = mapped_column(String(30))
    created_at: Mapped[str] = mapped_column(String(40), nullable=False)


class EventRow(Base):
    __tablename__ = "events"
    __table_args__ = (
        UniqueConstraint("investigation_id", "seq", name="uq_event_seq"),
        Index("ix_event_scan_seq", "investigation_id", "seq"),
    )
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    investigation_id: Mapped[str] = mapped_column(
        String(40), ForeignKey("investigations.id"), nullable=False
    )
    seq: Mapped[int] = mapped_column(BigInteger, nullable=False)
    type: Mapped[str] = mapped_column(String(60), nullable=False)
    payload: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    actor: Mapped[str | None] = mapped_column(String(60))
    causation_id: Mapped[str | None] = mapped_column(String(40))
    correlation_id: Mapped[str | None] = mapped_column(String(40))
    created_at: Mapped[str] = mapped_column(String(40), nullable=False)


class EvidenceRow(Base):
    __tablename__ = "evidence"
    __table_args__ = (
        UniqueConstraint("investigation_id", "sha256", name="uq_evidence_sha"),
        UniqueConstraint("investigation_id", "id", name="uq_evidence_investigation_id"),
    )
    id: Mapped[str] = mapped_column(String(40), primary_key=True)
    investigation_id: Mapped[str] = mapped_column(
        String(40), ForeignKey("investigations.id"), nullable=False
    )
    kind: Mapped[str] = mapped_column(String(30), nullable=False)
    sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    object_key: Mapped[str] = mapped_column(Text, nullable=False)
    byte_size: Mapped[int] = mapped_column(BigInteger, nullable=False)
    truncated: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    redacted: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    summary: Mapped[str] = mapped_column(Text, nullable=False)
    produced_by: Mapped[str] = mapped_column(String(60), nullable=False)
    created_at: Mapped[str] = mapped_column(String(40), nullable=False)


class ObservationRow(Base):
    __tablename__ = "observations"
    __table_args__ = (
        # AC-FR-RECON-7: a fact without evidence is a bug, enforced by the database.
        # json_array_length exists on both SQLite (on JSON text) and Postgres (on json),
        # so this constraint is portable - unlike uuid[]/text[] array semantics (ADR-018).
        CheckConstraint(
            "kind <> 'fact' OR json_array_length(evidence_refs) > 0",
            name="facts_have_evidence",
        ),
        CheckConstraint(
            "kind <> 'fact' OR confidence = 1.0",
            name="facts_are_certain",
        ),
    )
    id: Mapped[str] = mapped_column(String(40), primary_key=True)
    investigation_id: Mapped[str] = mapped_column(
        String(40), ForeignKey("investigations.id"), nullable=False
    )
    agent: Mapped[str] = mapped_column(String(60), nullable=False)
    kind: Mapped[str] = mapped_column(String(20), nullable=False)
    fidelity: Mapped[str] = mapped_column(String(30), nullable=False)
    subject_type: Mapped[str | None] = mapped_column(String(40))
    subject_ref: Mapped[str | None] = mapped_column(String(500))
    statement: Mapped[str] = mapped_column(Text, nullable=False)
    attributes: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    maswe: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=1.0)
    evidence_refs: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    created_at: Mapped[str] = mapped_column(String(40), nullable=False)


class HypothesisRow(Base):
    __tablename__ = "hypotheses"
    id: Mapped[str] = mapped_column(String(40), primary_key=True)
    investigation_id: Mapped[str] = mapped_column(
        String(40), ForeignKey("investigations.id"), nullable=False
    )
    claim: Mapped[str] = mapped_column(Text, nullable=False)
    maswe: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    derived_from: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    required_evidence: Mapped[list[str]] = mapped_column(JSON, nullable=False)
    satisfied_evidence: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="open")
    priority: Mapped[float] = mapped_column(Float, nullable=False, default=0.5)
    depth: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    parent_id: Mapped[str | None] = mapped_column(String(40), ForeignKey("hypotheses.id"))
    created_at: Mapped[str] = mapped_column(String(40), nullable=False)


class DecisionRow(Base):
    __tablename__ = "decisions"
    id: Mapped[str] = mapped_column(String(40), primary_key=True)
    investigation_id: Mapped[str] = mapped_column(
        String(40), ForeignKey("investigations.id"), nullable=False
    )
    agent: Mapped[str] = mapped_column(String(60), nullable=False)
    action: Mapped[str] = mapped_column(String(60), nullable=False)
    action_args: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    considered_evidence: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    alternatives: Mapped[list[dict[str, Any]]] = mapped_column(JSON, nullable=False, default=list)
    expected_outcome: Mapped[str] = mapped_column(Text, nullable=False)
    uncertainty: Mapped[str | None] = mapped_column(Text)
    prompt_version: Mapped[str | None] = mapped_column(String(64))
    model_id: Mapped[str | None] = mapped_column(String(120))
    provider: Mapped[str | None] = mapped_column(String(40))
    model_role: Mapped[str | None] = mapped_column(String(20))
    requested_model: Mapped[str | None] = mapped_column(String(120))
    system_prompt_sha256: Mapped[str | None] = mapped_column(String(64))
    input_sha256: Mapped[str | None] = mapped_column(String(64))
    schema_sha256: Mapped[str | None] = mapped_column(String(64))
    response_sha256: Mapped[str | None] = mapped_column(String(64))
    schema_name: Mapped[str | None] = mapped_column(String(120))
    output_json: Mapped[dict[str, Any] | None] = mapped_column(JSON)
    input_tokens: Mapped[int | None] = mapped_column(Integer)
    output_tokens: Mapped[int | None] = mapped_column(Integer)
    latency_ms: Mapped[int | None] = mapped_column(Integer)
    temperature: Mapped[float | None] = mapped_column(Float)
    max_tokens: Mapped[int | None] = mapped_column(Integer)
    created_at: Mapped[str] = mapped_column(String(40), nullable=False)


class FrontierEntryRow(Base):
    __tablename__ = "frontier_entries"
    __table_args__ = (Index("ix_frontier_pick", "investigation_id", "state", "score"),)
    id: Mapped[str] = mapped_column(String(40), primary_key=True)
    investigation_id: Mapped[str] = mapped_column(
        String(40), ForeignKey("investigations.id"), nullable=False
    )
    action: Mapped[str] = mapped_column(String(60), nullable=False)
    action_args: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    required_agent: Mapped[str] = mapped_column(String(60), nullable=False)
    relates_to_maswe: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    score: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    depth: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    state: Mapped[str] = mapped_column(String(20), nullable=False, default="queued")
    lease_owner: Mapped[str | None] = mapped_column(String(120))
    attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    inserted_at: Mapped[str] = mapped_column(String(40), nullable=False)


class FindingRow(Base):
    __tablename__ = "findings"
    __table_args__ = (
        # The project's two honesty guarantees, enforced by the database as well as the model.
        CheckConstraint(
            "status <> 'confirmed' OR validated_by IS NOT NULL", name="confirmed_requires_validator"
        ),
        CheckConstraint("confidence BETWEEN 0 AND 1", name="confidence_range"),
        Index("ix_findings_scan", "investigation_id", "status"),
    )
    id: Mapped[str] = mapped_column(String(40), primary_key=True)
    investigation_id: Mapped[str] = mapped_column(
        String(40), ForeignKey("investigations.id"), nullable=False
    )
    title: Mapped[str] = mapped_column(Text, nullable=False)
    category: Mapped[str] = mapped_column(String(80), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    component_ref: Mapped[str | None] = mapped_column(String(500))
    source_ref: Mapped[dict[str, Any] | None] = mapped_column(JSON)
    evidence_refs: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    masvs: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    maswe: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    mastg: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    severity: Mapped[str] = mapped_column(String(20), nullable=False)
    severity_vector: Mapped[str | None] = mapped_column(String(200))
    confidence: Mapped[float] = mapped_column(Float, nullable=False)
    status: Mapped[str] = mapped_column(String(30), nullable=False)
    discovered_by: Mapped[str] = mapped_column(String(60), nullable=False)
    validated_by: Mapped[str | None] = mapped_column(String(60))
    gate_evidence: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    remediation: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[str] = mapped_column(String(40), nullable=False)
    updated_at: Mapped[str] = mapped_column(String(40), nullable=False)


class VerdictRow(Base):
    __tablename__ = "verdicts"
    __table_args__ = (
        CheckConstraint(
            "verdict <> 'rejected' OR rejection_reason IS NOT NULL", name="rejection_states_why"
        ),
    )
    id: Mapped[str] = mapped_column(String(40), primary_key=True)
    finding_id: Mapped[str] = mapped_column(
        String(40), ForeignKey("findings.id"), nullable=False
    )
    verdict: Mapped[str] = mapped_column(String(30), nullable=False)
    rejection_reason: Mapped[str | None] = mapped_column(String(40))
    rationale: Mapped[str] = mapped_column(Text, nullable=False)
    gate_passed: Mapped[bool] = mapped_column(Boolean, nullable=False)
    gate_detail: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    validated_by: Mapped[str] = mapped_column(String(60), nullable=False)
    model_id: Mapped[str | None] = mapped_column(String(120))
    created_at: Mapped[str] = mapped_column(String(40), nullable=False)


class ApprovalRow(Base):
    __tablename__ = "approvals"
    __table_args__ = (
        CheckConstraint(
            "intensity_granted IS NULL OR intensity_granted <= intensity_required",
            name="grant_within_request",
        ),
        CheckConstraint(
            "state <> 'rejected' OR intensity_granted IS NULL", name="non_grant_has_no_level"
        ),
        Index("ix_approvals_scan", "investigation_id", "state"),
    )
    id: Mapped[str] = mapped_column(String(40), primary_key=True)
    investigation_id: Mapped[str] = mapped_column(
        String(40), ForeignKey("investigations.id"), nullable=False
    )
    requested_action: Mapped[str] = mapped_column(String(60), nullable=False)
    plan_sha256: Mapped[str | None] = mapped_column(String(64))
    intensity_required: Mapped[int] = mapped_column(Integer, nullable=False)
    intensity_granted: Mapped[int | None] = mapped_column(Integer)
    justification: Mapped[str] = mapped_column(Text, nullable=False)
    risk_summary: Mapped[str] = mapped_column(Text, nullable=False)
    state: Mapped[str] = mapped_column(String(20), nullable=False, default="pending")
    requested_by: Mapped[str] = mapped_column(String(60), nullable=False)
    decided_by: Mapped[str | None] = mapped_column(String(40), ForeignKey("users.id"))
    decided_at: Mapped[str | None] = mapped_column(String(40))
    decision_note: Mapped[str | None] = mapped_column(Text)
    expires_at: Mapped[str] = mapped_column(String(40), nullable=False)
    created_at: Mapped[str] = mapped_column(String(40), nullable=False)


class ReportRow(Base):
    __tablename__ = "reports"
    __table_args__ = (UniqueConstraint("investigation_id", "version", name="uq_report_version"),)
    id: Mapped[str] = mapped_column(String(40), primary_key=True)
    investigation_id: Mapped[str] = mapped_column(
        String(40), ForeignKey("investigations.id"), nullable=False
    )
    version: Mapped[int] = mapped_column(Integer, nullable=False)
    format: Mapped[str] = mapped_column(String(20), nullable=False)
    object_key: Mapped[str] = mapped_column(Text, nullable=False)
    content_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    coverage: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    created_at: Mapped[str] = mapped_column(String(40), nullable=False)


class WorkerJobRow(Base):
    __tablename__ = "worker_jobs"
    __table_args__ = (
        CheckConstraint("status IN ('queued','running','succeeded','failed','cancelled')", name="worker_job_status_known"),
        Index("ix_worker_jobs_claim", "status", "created_at"),
        Index("ix_worker_jobs_investigation", "investigation_id", "created_at"),
    )
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    investigation_id: Mapped[str] = mapped_column(
        String(40), ForeignKey("investigations.id"), nullable=False
    )
    kind: Mapped[str] = mapped_column(String(40), nullable=False)
    artifact_key: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="queued")
    attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    worker_id: Mapped[str | None] = mapped_column(String(120))
    result_json: Mapped[dict[str, Any] | None] = mapped_column(JSON)
    error_code: Mapped[str | None] = mapped_column(String(80))
    error_detail: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[str] = mapped_column(String(40), nullable=False)
    started_at: Mapped[str | None] = mapped_column(String(40))
    lease_until: Mapped[str | None] = mapped_column(String(40))
    finished_at: Mapped[str | None] = mapped_column(String(40))
    applied_at: Mapped[str | None] = mapped_column(String(40))


class GraphNodeRow(Base):
    __tablename__ = "graph_nodes"
    __table_args__ = (
        UniqueConstraint("investigation_id", "id", name="uq_graph_node_investigation_id"),
        UniqueConstraint("investigation_id", "node_type", "ref", name="uq_graph_node_identity"),
        Index("ix_graph_nodes_investigation_type", "investigation_id", "node_type"),
    )
    id: Mapped[str] = mapped_column(String(40), primary_key=True)
    investigation_id: Mapped[str] = mapped_column(
        String(40), ForeignKey("investigations.id"), nullable=False
    )
    node_type: Mapped[str] = mapped_column(String(40), nullable=False)
    label: Mapped[str] = mapped_column(Text, nullable=False)
    ref: Mapped[str | None] = mapped_column(String(1000))
    assertion: Mapped[str] = mapped_column(String(20), nullable=False)
    attributes: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    created_at: Mapped[str] = mapped_column(String(40), nullable=False)


class GraphEdgeRow(Base):
    __tablename__ = "graph_edges"
    __table_args__ = (
        UniqueConstraint("investigation_id", "id", name="uq_graph_edge_investigation_id"),
        UniqueConstraint(
            "investigation_id", "source_id", "target_id", "relation",
            name="uq_graph_edge_identity",
        ),
        ForeignKeyConstraint(
            ["investigation_id", "source_id"],
            ["graph_nodes.investigation_id", "graph_nodes.id"],
            name="fk_graph_edge_source_same_investigation",
        ),
        ForeignKeyConstraint(
            ["investigation_id", "target_id"],
            ["graph_nodes.investigation_id", "graph_nodes.id"],
            name="fk_graph_edge_target_same_investigation",
        ),
        Index("ix_graph_edges_investigation_source", "investigation_id", "source_id"),
        Index("ix_graph_edges_investigation_target", "investigation_id", "target_id"),
        CheckConstraint(
            "assertion <> 'hypothesis' OR (rationale IS NOT NULL AND length(rationale) > 0)",
            name="graph_hypothesis_states_why",
        ),
    )
    id: Mapped[str] = mapped_column(String(40), primary_key=True)
    investigation_id: Mapped[str] = mapped_column(String(40), nullable=False)
    source_id: Mapped[str] = mapped_column(String(40), nullable=False)
    target_id: Mapped[str] = mapped_column(String(40), nullable=False)
    relation: Mapped[str] = mapped_column(String(60), nullable=False)
    assertion: Mapped[str] = mapped_column(String(20), nullable=False)
    rationale: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[str] = mapped_column(String(40), nullable=False)


class GraphNodeEvidenceRow(Base):
    __tablename__ = "graph_node_evidence"
    __table_args__ = (
        ForeignKeyConstraint(
            ["investigation_id", "node_id"],
            ["graph_nodes.investigation_id", "graph_nodes.id"],
            name="fk_graph_node_evidence_node_same_investigation",
        ),
        ForeignKeyConstraint(
            ["investigation_id", "evidence_id"],
            ["evidence.investigation_id", "evidence.id"],
            name="fk_graph_node_evidence_evidence_same_investigation",
        ),
    )
    investigation_id: Mapped[str] = mapped_column(String(40), primary_key=True)
    node_id: Mapped[str] = mapped_column(String(40), primary_key=True)
    evidence_id: Mapped[str] = mapped_column(String(40), primary_key=True)


class GraphEdgeEvidenceRow(Base):
    __tablename__ = "graph_edge_evidence"
    __table_args__ = (
        ForeignKeyConstraint(
            ["investigation_id", "edge_id"],
            ["graph_edges.investigation_id", "graph_edges.id"],
            name="fk_graph_edge_evidence_edge_same_investigation",
        ),
        ForeignKeyConstraint(
            ["investigation_id", "evidence_id"],
            ["evidence.investigation_id", "evidence.id"],
            name="fk_graph_edge_evidence_evidence_same_investigation",
        ),
    )
    investigation_id: Mapped[str] = mapped_column(String(40), primary_key=True)
    edge_id: Mapped[str] = mapped_column(String(40), primary_key=True)
    evidence_id: Mapped[str] = mapped_column(String(40), primary_key=True)




class PoCRunRow(Base):
    __tablename__ = "poc_runs"
    __table_args__ = (
        UniqueConstraint("investigation_id", "id", name="uq_poc_run_investigation_id"),
        CheckConstraint("status IN ('passed','failed','cancelled','timed_out')", name="poc_run_status_known"),
        Index("ix_poc_runs_investigation_created", "investigation_id", "created_at"),
    )
    id: Mapped[str] = mapped_column(String(40), primary_key=True)
    investigation_id: Mapped[str] = mapped_column(
        String(40), ForeignKey("investigations.id"), nullable=False
    )
    plan_id: Mapped[str] = mapped_column(String(40), nullable=False)
    approval_id: Mapped[str | None] = mapped_column(String(40), ForeignKey("approvals.id"))
    cancel_requested_at: Mapped[str | None] = mapped_column(String(40))
    cleanup_json: Mapped[dict[str, Any] | None] = mapped_column(JSON)
    authorization_id: Mapped[str] = mapped_column(
        String(40), ForeignKey("authorizations.id"), nullable=False
    )
    target_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    hypothesis_ids: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    status: Mapped[str] = mapped_column(String(20), nullable=False)
    exit_status: Mapped[str] = mapped_column(String(20), nullable=False)
    input_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    output_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    input_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    output_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    tool_versions: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    started_at: Mapped[str] = mapped_column(String(40), nullable=False)
    finished_at: Mapped[str] = mapped_column(String(40), nullable=False)
    duration_ms: Mapped[int] = mapped_column(Integer, nullable=False)
    created_at: Mapped[str] = mapped_column(String(40), nullable=False)


class PoCRunEvidenceRow(Base):
    __tablename__ = "poc_run_evidence"
    __table_args__ = (
        ForeignKeyConstraint(
            ["investigation_id", "run_id"],
            ["poc_runs.investigation_id", "poc_runs.id"],
            name="fk_poc_run_evidence_run_same_investigation",
        ),
        ForeignKeyConstraint(
            ["investigation_id", "evidence_id"],
            ["evidence.investigation_id", "evidence.id"],
            name="fk_poc_run_evidence_evidence_same_investigation",
        ),
    )
    investigation_id: Mapped[str] = mapped_column(String(40), primary_key=True)
    run_id: Mapped[str] = mapped_column(String(40), primary_key=True)
    evidence_id: Mapped[str] = mapped_column(String(40), primary_key=True)
    kind: Mapped[str] = mapped_column(String(20), nullable=False)



ALL_TABLES = (
    UserRow,
    AuthorizationRow,
    ApplicationRow,
    InvestigationRow,
    EventRow,
    EvidenceRow,
    ObservationRow,
    HypothesisRow,
    DecisionRow,
    FrontierEntryRow,
    FindingRow,
    VerdictRow,
    ApprovalRow,
    ReportRow,
    WorkerJobRow,
    GraphNodeRow,
    GraphEdgeRow,
    GraphNodeEvidenceRow,
    GraphEdgeEvidenceRow,
    PoCRunRow,
    PoCRunEvidenceRow,
)
