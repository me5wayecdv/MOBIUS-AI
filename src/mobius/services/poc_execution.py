"""Persist reproducible PoC plans, results and evidence (D-042)."""
from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from typing import Any
from threading import Event, Lock

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..adapters.events import SqlEventStore, utcnow
from ..adapters.models import PoCRunEvidenceRow, PoCRunRow
from ..core.enums import EvidenceKind
from ..core.ids import IdPrefix, new_id
from ..core.schemas import PoCTestPlan
from .evidence import EvidenceService
from .poc_runner import PoCExecutionResult, SafePoCRunner

_CANCEL_EVENTS: dict[str, Event] = {}
_CANCEL_LOCK = Lock()


def request_poc_cancel(plan_id: str) -> bool:
    """Signal an active plan in this process; cancellation is cooperative between steps."""
    with _CANCEL_LOCK:
        event = _CANCEL_EVENTS.get(plan_id)
        if event is None:
            return False
        event.set()
        return True


@dataclass(frozen=True, slots=True)
class PersistedPoCExecution:
    run_id: str
    plan_id: str
    investigation_id: str
    status: str
    input_sha256: str
    output_sha256: str
    evidence_ids: tuple[str, ...]
    result: PoCExecutionResult


class PoCExecutionService:
    """Execute through the D-041 allowlist and persist the complete reproducibility record."""

    def __init__(self, session: Session, artifact_store) -> None:
        self.session = session
        self.artifact_store = artifact_store

    def execute_and_persist(self, plan: PoCTestPlan) -> PersistedPoCExecution:
        cancel_event = Event()
        with _CANCEL_LOCK:
            if plan.id in _CANCEL_EVENTS:
                raise RuntimeError("a PoC execution with this plan ID is already running")
            _CANCEL_EVENTS[plan.id] = cancel_event
        try:
            from .phantom import adapter_from_env
            result = SafePoCRunner(
                self.session, emulator_adapter=adapter_from_env()
            ).run(plan, cancel_check=cancel_event.is_set)
        finally:
            with _CANCEL_LOCK:
                _CANCEL_EVENTS.pop(plan.id, None)
        input_json = plan.model_dump(mode="json")
        output_json = asdict(result)
        input_bytes = json.dumps(input_json, sort_keys=True, separators=(",", ":")).encode()
        output_bytes = json.dumps(output_json, sort_keys=True, separators=(",", ":"), default=str).encode()
        log_text = "\n".join(
            f"[{step.index}] {step.action} {step.target_ref}: {step.status} "
            f"tool={step.tool_name}/{step.tool_version} duration_ms={step.duration_ms}"
            for step in result.steps
        ).encode("utf-8")
        input_sha = hashlib.sha256(input_bytes).hexdigest()
        output_sha = hashlib.sha256(output_bytes).hexdigest()

        evidence = EvidenceService(self.session, self.artifact_store)
        plan_evidence = evidence.record(
            investigation_id=plan.investigation_id,
            kind=EvidenceKind.POC_PLAN,
            content=input_bytes,
            summary=f"PoC plan {plan.id}; target SHA-256 {plan.target_sha256}",
            produced_by="POC",
        )
        result_evidence = evidence.record(
            investigation_id=plan.investigation_id,
            kind=EvidenceKind.POC_RESULT,
            content=output_bytes,
            summary=f"PoC run result {plan.id}; status {result.status}",
            produced_by="POC",
        )
        log_evidence = evidence.record(
            investigation_id=plan.investigation_id,
            kind=EvidenceKind.POC_LOG,
            content=log_text or b"No step output",
            summary=f"PoC execution log {plan.id}",
            produced_by="POC",
        )
        run_id = new_id(IdPrefix.POC_RUN)
        row = PoCRunRow(
            id=run_id,
            investigation_id=plan.investigation_id,
            plan_id=plan.id,
            approval_id=plan.approval_id,
            cancel_requested_at=utcnow() if result.status == "cancelled" else None,
            cleanup_json={"steps": list(result.cleanup_results)},
            authorization_id=plan.authorization_id,
            target_sha256=plan.target_sha256,
            hypothesis_ids=list(plan.hypothesis_ids),
            status=result.status,
            exit_status={"passed": "success", "failed": "failure", "cancelled": "cancelled", "timed_out": "timed_out"}[result.status],
            input_sha256=input_sha,
            output_sha256=output_sha,
            input_json=input_json,
            output_json=output_json,
            tool_versions=list(result.tool_versions),
            started_at=result.started_at,
            finished_at=result.finished_at,
            duration_ms=result.duration_ms,
            created_at=utcnow(),
        )
        self.session.add(row)
        # Persist the parent run before inserting composite-FK evidence links.
        # This makes the ordering explicit for both SQLite and PostgreSQL.
        self.session.flush()
        for item, kind in (
            (plan_evidence, "plan"), (result_evidence, "result"), (log_evidence, "log")
        ):
            self.session.add(PoCRunEvidenceRow(
                investigation_id=plan.investigation_id,
                run_id=run_id,
                evidence_id=item.id,
                kind=kind,
            ))
        self.session.flush()
        SqlEventStore(self.session).emit(
            plan.investigation_id,
            "poc_completed",
            {
                "run_id": run_id,
                "plan_id": plan.id,
                "status": result.status,
                "target_sha256": plan.target_sha256,
                "input_sha256": input_sha,
                "output_sha256": output_sha,
                "evidence_ids": [plan_evidence.id, result_evidence.id, log_evidence.id],
                "tool_versions": list(result.tool_versions),
                "duration_ms": result.duration_ms,
            },
            actor="POC",
        )
        return PersistedPoCExecution(
            run_id=run_id,
            plan_id=plan.id,
            investigation_id=plan.investigation_id,
            status=result.status,
            input_sha256=input_sha,
            output_sha256=output_sha,
            evidence_ids=(plan_evidence.id, result_evidence.id, log_evidence.id),
            result=result,
        )

    def get(self, run_id: str) -> PoCRunRow:
        row = self.session.get(PoCRunRow, run_id)
        if row is None:
            raise LookupError(f"PoC run {run_id} not found")
        return row

    def evidence_for(self, run_id: str) -> list[dict[str, Any]]:
        row = self.get(run_id)
        links = self.session.execute(
            select(PoCRunEvidenceRow).where(
                PoCRunEvidenceRow.investigation_id == row.investigation_id,
                PoCRunEvidenceRow.run_id == run_id,
            ).order_by(PoCRunEvidenceRow.kind)
        ).scalars()
        return [{"evidence_id": link.evidence_id, "kind": link.kind} for link in links]
