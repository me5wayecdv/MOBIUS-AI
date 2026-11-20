"""NEXUS: the bounded loop that actually drives the tools.

What this is: a deterministic dispatcher. It pops the best-scoring entry off the frontier,
hands it to the agent that can execute it, records the outcome, and repeats until the
frontier is empty or the step budget is spent. The ranking is arithmetic
(``core/frontier.py``), the dispatch table is a dict, and there is no model anywhere in it.

What this is **not**: adaptive planning. The design documents describe an agent that
re-plans when an action returns nothing interesting. This loop cannot do that, because
re-planning is the one thing here that genuinely needs a model, and no model is called in
this build. Calling it "autonomous" would be the exact overclaim the project forbids, so the
response, the events and the status file all say dispatcher.

Two properties matter as much as the dispatching:

* **The budget is a real stop, not a hint.** ``max_steps`` bounds dispatches; when it is hit
  the FSM moves to BUDGET_EXHAUSTED and the investigation still closes with a record of what
  was left undone. A loop that cannot say what it skipped is not auditable.
* **Work with no executor is reported, not dropped quietly.** A frontier entry for PHANTOM
  or for an action this build has no implementation of stays in the record as ``dropped``
  with the reason. The frontier's design note says the same thing: the "what we did not do"
  section depends on those entries surviving.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from sqlalchemy.orm import Session

from ..adapters.events import SqlEventStore, utcnow
from ..adapters.models import DecisionRow, FrontierEntryRow, InvestigationRow
from ..core import frontier
from ..core.actions import ActionRegistry, ActionRejected
from ..core.enums import FindingStatus, InvestigationState, StopReason
from ..core.ids import IdPrefix, new_id
from ..core.schemas import FrontierEntry
from .archivist import ArchivistService
from .artifacts import ArtifactStore
from .errors import NotFound, ScanStateConflict
from .spectre import SpectreService
from .state import advance

AGENT = "NEXUS"

#: Dispatch table: frontier action -> the agent implementation that performs it.
#: Only what exists. A missing key is reported as a dropped entry with a reason, never
#: invented into a success.
_EXECUTORS: dict[str, str] = {
    "find_api_refs": "SPECTRE",
    "callers_of": "SPECTRE",
}

#: Why an agent named in the frontier cannot be run in this build.
_UNAVAILABLE: dict[str, str] = {
    "PHANTOM": "PHANTOM is not implemented and no emulator is available (R-02, ADR-016)",
    "VECTOR": "VECTOR is not implemented and the sandbox has no egress (R-01)",
    "ORACLE": "ORACLE is deliberately out of v1 scope",
    "ARCHIVIST": "ARCHIVIST report writing is not implemented (phase 8)",
}

DEFAULT_MAX_STEPS = 20
DEFAULT_MAX_DEPTH = 4


@dataclass(frozen=True, slots=True)
class Step:
    """One dispatch decision, kept whether or not it did anything."""

    entry_id: str
    action: str
    agent: str
    disposition: str  # "done" | "dropped" | "deferred"
    reason: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "entry_id": self.entry_id,
            "action": self.action,
            "agent": self.agent,
            "disposition": self.disposition,
            "reason": self.reason,
        }


class NexusService:
    def __init__(
        self,
        session: Session,
        store: ArtifactStore,
        *,
        spectre: SpectreService | None = None,
        max_steps: int = DEFAULT_MAX_STEPS,
        max_depth: int = DEFAULT_MAX_DEPTH,
        action_registry: ActionRegistry | None = None,
    ) -> None:
        self._session = session
        self._store = store
        self._spectre = spectre or SpectreService(session, store)
        self._max_steps = max_steps
        self._max_depth = max_depth
        self._action_registry = action_registry or ActionRegistry()

    def run(self, investigation_id: str, *, max_steps: int | None = None) -> dict[str, object]:
        """Drive the investigation from the frontier to CLOSED.

        Deterministic: no clock, no randomness, no model. The same frontier and the same
        budget produce the same dispatch order and the same verdicts.
        """
        row = self._row(investigation_id)
        state = InvestigationState(row.state)
        if state not in (InvestigationState.SURFACE_READY, InvestigationState.CORRELATING):
            raise ScanStateConflict(
                "NEXUS runs after RECON (or after a completed SPECTRE pass); "
                f"investigation is in {state.value}"
            )

        limit = self._max_steps if max_steps is None else max_steps
        if limit < 1:
            raise ValueError("max_steps must be at least 1: a loop that may not dispatch is a no-op")

        store = SqlEventStore(self._session)
        store.emit(
            investigation_id,
            "nexus_started",
            {"max_steps": limit, "intensity": row.intensity, "from_state": state.value},
            actor=AGENT,
        )

        index = None
        evidence_id: str | None = None
        candidate_count = 0
        if state is InvestigationState.SURFACE_READY:
            candidate_count = len(self._spectre.candidates(investigation_id))
            index, evidence = self._spectre.prepare(investigation_id)
            evidence_id = getattr(evidence, "id", None)
            self._advance(row, InvestigationState.SELECTING)

        stop = StopReason.COMPLETED
        steps: list[Step] = []
        outcomes: list[dict[str, object]] = []

        while True:
            queued = self._queued(investigation_id)
            if not queued:
                break

            ctx = frontier.ScoreContext(
                intensity=row.intensity, max_depth=self._max_depth
            )
            best = frontier.pop_best([self._as_domain(r) for r in queued], ctx)

            if best is None:
                # Everything queued is forbidden at this intensity. Drop with a reason: the
                # entries must survive into the report as work that was not permitted.
                for entry in queued:
                    steps.append(
                        self._drop(
                            entry,
                            f"intensity {row.intensity} does not permit {entry.action}",
                        )
                    )
                break

            if len(steps) >= limit:
                stop = StopReason.BUDGET_EXHAUSTED
                self._advance(row, InvestigationState.BUDGET_EXHAUSTED)
                break

            entry_row = self._session.get(FrontierEntryRow, best.id)
            self._advance(row, InvestigationState.DISPATCHING)
            step, outcome = self._dispatch(row, entry_row, index, evidence_id)
            steps.append(step)
            if outcome is not None:
                outcomes.append(outcome)
                if entry_row.action == "find_api_refs":
                    self._replan_after_result(row, entry_row, outcome)
            self._advance(row, InvestigationState.OBSERVING)
            if step.disposition == "deferred":
                # The entry stays queued on purpose; re-popping it would spin forever.
                break
            if not self._queued(investigation_id):
                # Nothing left to pick: OBSERVING is the only state with an edge into
                # VALIDATING, so the loop must close out from here rather than SELECTING.
                self._advance(row, InvestigationState.VALIDATING)
                break
            self._advance(row, InvestigationState.SELECTING)

        # Close out along the edges the FSM actually has. Validation happened per candidate
        # inside the dispatch, so VALIDATING here is the loop's own pass over the results.
        state = InvestigationState(row.state)
        if state is InvestigationState.OBSERVING:
            self._advance(row, InvestigationState.VALIDATING)
            state = InvestigationState.VALIDATING
        if state is InvestigationState.VALIDATING:
            self._advance(row, InvestigationState.CORRELATING)
            state = InvestigationState.CORRELATING
        if state is InvestigationState.SELECTING:
            # No work was ever dispatched (or none was left): SELECTING may go straight to
            # CORRELATING, skipping a validation pass over an empty result set.
            self._advance(row, InvestigationState.CORRELATING)
            state = InvestigationState.CORRELATING
        if state in (InvestigationState.CORRELATING, InvestigationState.BUDGET_EXHAUSTED):
            self._advance(row, InvestigationState.REPORTING)
            state = InvestigationState.REPORTING
        report_id: str | None = None
        if state is InvestigationState.REPORTING:
            self._advance(row, InvestigationState.CLOSED, reason=stop.value)

        row.stop_reason = stop.value
        self._session.flush()

        # The report is written *after* closure, not during REPORTING. Written inside
        # REPORTING it described the scan as still reporting, with no stop reason - the one
        # field a reader most needs, wrong, in the one document they keep.
        if InvestigationState(row.state) is InvestigationState.CLOSED:
            try:
                written = ArchivistService(self._session, self._store).write(investigation_id)
                report_id = written["evidence_id"]
            except Exception as exc:  # noqa: BLE001 - closure must not depend on rendering
                SqlEventStore(self._session).emit(
                    investigation_id,
                    "report_failed",
                    {"error": f"{type(exc).__name__}: {exc}"},
                    actor=AGENT,
                )

        dispatched = [s for s in steps if s.disposition == "done"]
        dropped = [s for s in steps if s.disposition == "dropped"]
        remaining = len(self._queued(investigation_id))
        counts = self._counts(outcomes)

        notes: list[str] = []
        if remaining:
            notes.append(
                f"{remaining} frontier entr{'y' if remaining == 1 else 'ies'} left queued: "
                "the step budget stopped the loop before they ran"
            )
        notes.append(
            f"report artefact {report_id} written by ARCHIVIST"
            if report_id
            else "no report artefact was written: report generation failed and is recorded "
            "as report_failed in the event log"
        )
        if dropped:
            notes.append(
                f"{len(dropped)} entr{'y' if len(dropped) == 1 else 'ies'} dropped for want "
                "of an executor; the reasons are in steps"
            )

        if dispatched:
            # The stream's contract is that `code_analysis_complete` marks the end of code
            # analysis, whoever drove it. NEXUS dispatches SPECTRE's work, so it owes the
            # stream the same event rather than leaving a consumer waiting for a marker that
            # only the single-shot SPECTRE endpoint used to emit.
            store.emit(
                investigation_id,
                "code_analysis_complete",
                {
                    "classes": len(index.classes) if index is not None else 0,
                    "methods": index.methods if index is not None else 0,
                    "candidates": candidate_count,
                    "confirmed": counts["confirmed"],
                    "rejected": counts["rejected"],
                    "manual_review": counts["manual_review"],
                    "executed_by": AGENT,
                },
                actor=AGENT,
            )

        store.emit(
            investigation_id,
            "nexus_complete",
            {
                "stop_reason": stop.value,
                "steps": len(steps),
                "max_steps": limit,
                "dispatched": len(dispatched),
                "dropped": len(dropped),
                "remaining": remaining,
                "confirmed": counts["confirmed"],
                "rejected": counts["rejected"],
                "manual_review": counts["manual_review"],
            },
            actor=AGENT,
        )
        self._session.flush()

        return {
            "state": row.state,
            "stop_reason": stop.value,
            "candidates": candidate_count,
            "budget": {
                "max_steps": limit,
                "steps_used": len(steps),
                "steps_remaining": max(limit - len(steps), 0),
            },
            "dispatched": len(dispatched),
            "dropped": len(dropped),
            "remaining": remaining,
            "findings": counts,
            "results": outcomes,
            "steps": [s.as_dict() for s in steps],
            "report_id": report_id,
            "notes": notes,
        }

    # -- internals -----------------------------------------------------------------

    def _row(self, investigation_id: str) -> InvestigationRow:
        row = self._session.get(InvestigationRow, investigation_id)
        if row is None:
            raise NotFound(f"investigation {investigation_id} not found")
        return row

    def _advance(self, row: InvestigationRow, target: InvestigationState, *, reason=None) -> None:
        advance(self._session, row, target, actor=AGENT, reason=reason)

    def _queued(self, investigation_id: str) -> list[FrontierEntryRow]:
        return (
            self._session.query(FrontierEntryRow)
            .filter(
                FrontierEntryRow.investigation_id == investigation_id,
                FrontierEntryRow.state == "queued",
            )
            .order_by(FrontierEntryRow.inserted_at.asc(), FrontierEntryRow.id.asc())
            .all()
        )

    @staticmethod
    def _as_domain(row: FrontierEntryRow) -> FrontierEntry:
        return FrontierEntry(
            id=row.id,
            investigation_id=row.investigation_id,
            action=row.action,
            action_args=row.action_args or {},
            required_agent=row.required_agent,
            relates_to_maswe=tuple(row.relates_to_maswe or ()),
            gate_category=row.gate_category,
            score=row.score or 0.0,
            depth=row.depth or 0,
            state=row.state,
            attempts=row.attempts or 0,
        )

    def _drop(self, entry: FrontierEntryRow, reason: str) -> Step:
        entry.state = "dropped"
        self._session.flush()
        SqlEventStore(self._session).emit(
            entry.investigation_id,
            "frontier_dropped",
            {"entry_id": entry.id, "action": entry.action, "reason": reason},
            actor=AGENT,
        )
        return Step(entry.id, entry.action, entry.required_agent, "dropped", reason)

    def _dispatch(
        self,
        row: InvestigationRow,
        entry: FrontierEntryRow,
        index,
        evidence_id: str | None,
    ) -> tuple[Step, dict[str, object] | None]:
        entry.attempts = (entry.attempts or 0) + 1
        executor = _EXECUTORS.get(entry.action)
        agent = entry.required_agent

        if executor != agent:
            reason = _UNAVAILABLE.get(
                agent, f"no executor is registered for {agent}/{entry.action}"
            )
            return self._drop(entry, reason), None

        try:
            _spec, validated_args = self._action_registry.validate(
                entry.action,
                entry.action_args or {},
                required_agent=agent,
                intensity=row.intensity,
            )
        except ActionRejected as exc:
            return self._drop(entry, f"action policy rejected dispatch: {exc}"), None
        entry.action_args = validated_args

        if index is None or evidence_id is None:
            # Arrived already in CORRELATING: the graph was built by an earlier call and is
            # not retained on the row. Re-dispatching without it would mean inventing a
            # result, so the entry is deferred rather than claimed as done.
            entry.state = "queued"
            self._session.flush()
            return (
                Step(
                    entry.id,
                    entry.action,
                    agent,
                    "deferred",
                    "no call graph in scope: NEXUS started after SPECTRE already finished",
                ),
                None,
            )

        SqlEventStore(self._session).emit(
            row.id,
            "frontier_dispatched",
            {"entry_id": entry.id, "action": entry.action, "agent": agent},
            actor=AGENT,
        )
        if entry.action == "callers_of":
            outcome = self._spectre.inspect_callers(row.id, entry, index, evidence_id)
        else:
            outcome = self._spectre.investigate(row.id, entry, index, evidence_id)
        entry.state = "done" if outcome is not None else "dropped"
        self._session.flush()
        reason = None if outcome is not None else "the entry carried no component to analyse"
        return Step(entry.id, entry.action, agent, "done", reason), outcome

    def _replan_after_result(
        self,
        investigation: InvestigationRow,
        source_entry: FrontierEntryRow,
        outcome: dict[str, object],
    ) -> None:
        """Turn a newly observed reachable path into one typed caller-inspection action."""
        if outcome.get("reachability") != "reached":
            return
        path = outcome.get("method_path")
        if not isinstance(path, list) or not path:
            return
        target = path[-1]
        if not isinstance(target, dict):
            return
        args = {
            "target_class": target.get("class_name"),
            "target_method": target.get("name"),
            "target_descriptor": target.get("descriptor") or "",
        }
        try:
            self._action_registry.validate(
                "callers_of", args, required_agent="SPECTRE",
                intensity=investigation.intensity,
            )
        except ActionRejected:
            return

        duplicate = self._session.query(FrontierEntryRow).filter(
            FrontierEntryRow.investigation_id == investigation.id,
            FrontierEntryRow.action == "callers_of",
            FrontierEntryRow.action_args == args,
            FrontierEntryRow.state.in_(("queued", "done")),
        ).first()
        if duplicate is not None or (source_entry.depth or 0) >= self._max_depth:
            return

        observation_id = outcome.get("observation_id")
        entry = FrontierEntryRow(
            id=new_id(IdPrefix.FRONTIER),
            investigation_id=investigation.id,
            action="callers_of",
            action_args=args,
            required_agent="SPECTRE",
            relates_to_maswe=list(outcome.get("maswe") or []),
            score=max(0.0, min(1.0, float(source_entry.score or 0.5) + 0.1)),
            depth=(source_entry.depth or 0) + 1,
            state="queued",
            attempts=0,
            inserted_at=utcnow(),
        )
        self._session.add(entry)
        decision = DecisionRow(
            id=new_id(IdPrefix.DECISION),
            investigation_id=investigation.id,
            agent=AGENT,
            action="adaptive_replan",
            action_args={
                "source_action": source_entry.action,
                "next_action": "callers_of",
                "target_method": args,
            },
            considered_evidence=[observation_id] if observation_id else [],
            alternatives=["stop_component_investigation"],
            expected_outcome="Inspect direct callers of the method containing the reachable sink call.",
            uncertainty="Direct caller edges are bytecode references; they do not prove runtime execution or tainted input.",
            prompt_version="nexus-adaptive-replan-v1-deterministic",
            model_id=None,
            created_at=utcnow(),
        )
        self._session.add(decision)
        self._session.flush()
        SqlEventStore(self._session).emit(
            investigation.id,
            "nexus_replanned",
            {
                "source_entry_id": source_entry.id,
                "source_observation_id": observation_id,
                "next_entry_id": entry.id,
                "next_action": "callers_of",
                "target_method": args,
                "decision_id": decision.id,
                "mode": "deterministic_policy",
            },
            actor=AGENT,
        )

    @staticmethod
    def _counts(outcomes: list[dict[str, object]]) -> dict[str, int]:
        def count(status: str) -> int:
            return sum(1 for o in outcomes if o.get("status") == status)

        return {
            "confirmed": count(FindingStatus.CONFIRMED.value),
            "rejected": count(FindingStatus.REJECTED.value),
            "manual_review": count(FindingStatus.MANUAL_REVIEW_REQUIRED.value),
        }


__all__ = ["NexusService", "Step", "DEFAULT_MAX_STEPS"]
