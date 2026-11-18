"""SPECTRE: turn a component candidate into gate evidence.

This is the module where MOBIUS stops describing and starts concluding. RECON can only say
"this activity is exported". SPECTRE adds the two attributes the confirmation gates are
starved for - is a sensitive sink reachable from an entry point, and is there a caller check
on the way - and then asks the gate to decide.

What SPECTRE deliberately does *not* do:

* It does not call a model. A bounded graph search over dex call references is arithmetic.
  Putting a model here would make the answer non-reproducible for no gain, and the whole
  point of the gate is that confirmation is deterministic.
* It does not upgrade its own conclusions. A reachability result becomes an `inference`
  observation with a confidence below 1.0, because static reachability is not runtime
  reachability. The gate's `confirmed` verdict is about the *clause*, not about exploitability.
* It does not invent evidence when the search is inconclusive. A truncated traversal yields
  `None`, the gate reports missing evidence, and the finding lands in manual review. Silence
  is never reported as safety.
"""

from __future__ import annotations

from collections.abc import Callable

from sqlalchemy.orm import Session

from ..adapters.dex import CodeIndex, DexIndexError, index_apk
from ..adapters.events import SqlEventStore, utcnow
from ..adapters.models import (
    ApplicationRow,
    FrontierEntryRow,
    InvestigationRow,
    ObservationRow,
)
from ..core.enums import (
    EvidenceKind,
    FindingStatus,
    Fidelity,
    InvestigationState,
    ObservationKind,
)
from ..core.ids import IdPrefix, new_id
from ..core.reachability import MethodRef, ReachabilityResult, analyse
from ..core.sinks import entry_methods_for
from .artifacts import ArtifactStore
from .errors import CodeIndexFailed, NotFound, ScanStateConflict
from .evidence import EvidenceService
from .state import advance
from .validation import ValidationService

AGENT = "SPECTRE"
Indexer = Callable[..., CodeIndex]

# Confidence attached to a static reachability conclusion. Never 1.0: the traversal sees call
# references, not executed paths, so "reachable" means "a call path exists in bytecode".
_CONFIDENCE = {"reached-unguarded": 0.9, "reached-guarded": 0.8, "unknown": 0.5}


def _bucket(result: ReachabilityResult) -> str:
    """The evidence class of a reachability result.

    These values are caps, not scores: 1.0 is never reached, because no static search can
    show that a path executes or that its data is attacker-controlled (ADR-022).
    """
    if result.reached and not result.guarded:
        return "reached-unguarded"
    if result.reached:
        return "reached-guarded"
    return "unknown"


class SpectreService:
    def __init__(
        self,
        session: Session,
        store: ArtifactStore,
        *,
        indexer: Indexer = index_apk,
        max_depth: int = 8,
        max_nodes: int = 5000,
    ) -> None:
        self._session = session
        self._store = store
        self._indexer = indexer
        self._max_depth = max_depth
        self._max_nodes = max_nodes
        self._validator = ValidationService(session)

    def analyse(self, investigation_id: str) -> dict[str, object]:
        row = self._row(investigation_id)
        state = InvestigationState(row.state)
        if state is not InvestigationState.SURFACE_READY:
            raise ScanStateConflict(
                f"SPECTRE runs after RECON; investigation is in {state.value}"
            )

        index, evidence = self.prepare(investigation_id)

        self._advance(row, InvestigationState.SELECTING)
        candidates = self.candidates(investigation_id)
        self._advance(row, InvestigationState.DISPATCHING)

        results: list[dict[str, object]] = []
        self._advance(row, InvestigationState.OBSERVING)
        for entry in candidates:
            outcome = self.investigate(investigation_id, entry, index, evidence.id)
            if outcome is not None:
                results.append(outcome)
            entry.state = "done"
            entry.attempts = (entry.attempts or 0) + 1
        self._session.flush()

        self._advance(row, InvestigationState.VALIDATING)
        confirmed = sum(1 for r in results if r["status"] == FindingStatus.CONFIRMED.value)
        rejected = sum(1 for r in results if r["status"] == FindingStatus.REJECTED.value)
        review = sum(1 for r in results if r["status"] == FindingStatus.MANUAL_REVIEW_REQUIRED.value)

        SqlEventStore(self._session).emit(
            investigation_id,
            "code_analysis_complete",
            {
                "classes": len(index.classes),
                "methods": index.methods,
                "internal_calls": sum(len(v) for v in index.graph.edges.values()),
                "index_truncated": index.truncated,
                "index_complete": index.complete,
                "dex_coverage": [item.describe() for item in index.dex_coverage],
                "data_flow_findings": len(index.data_flows),
                "data_flow_methods": index.data_flow_methods,
                "data_flow_complete": index.data_flow_complete,
                "data_flow_limitations": list(index.data_flow_limitations),
                "candidates": len(candidates),
                "confirmed": confirmed,
                "rejected": rejected,
                "manual_review": review,
                "evidence_id": evidence.id,
            },
            actor=AGENT,
        )
        self._advance(row, InvestigationState.CORRELATING)
        self._session.flush()

        return {
            "state": row.state,
            "evidence_id": evidence.id,
            "index": index.describe(),
            "candidates": len(candidates),
            "confirmed": confirmed,
            "rejected": rejected,
            "manual_review": review,
            "results": results,
        }

    def prepare(self, investigation_id: str) -> tuple[CodeIndex, object]:
        """Index the APK and record the evidence, without moving the state.

        Separated from ``analyse`` so NEXUS can build the graph once and then dispatch
        candidates one at a time under its own budget, instead of this service deciding how
        much work to do.
        """
        row = self._row(investigation_id)
        if InvestigationState(row.state) is not InvestigationState.SURFACE_READY:
            raise ScanStateConflict(
                f"code analysis runs after RECON; investigation is in {row.state}"
            )
        application = self._session.get(ApplicationRow, row.application_id)
        index = self._build_index(application)
        evidence = self._record_index_evidence(investigation_id, index)
        self._session.flush()
        return index, evidence

    # -- internals -----------------------------------------------------------------

    def _row(self, investigation_id: str) -> InvestigationRow:
        row = self._session.get(InvestigationRow, investigation_id)
        if row is None:
            raise NotFound(f"investigation {investigation_id} not found")
        return row

    def _build_index(self, application: ApplicationRow | None) -> CodeIndex:
        if application is None:  # pragma: no cover - FK guarantees otherwise
            raise NotFound("application not found")
        try:
            apk = self._store.get(application.artifact_key)
        except (FileNotFoundError, OSError) as exc:
            raise CodeIndexFailed(
                f"artefact {application.artifact_key} is missing from storage"
            ) from exc
        try:
            return self._indexer(apk)
        except DexIndexError as exc:
            raise CodeIndexFailed(str(exc)) from exc

    def _record_index_evidence(self, investigation_id: str, index: CodeIndex):
        import json

        summary = {
            "classes": len(index.classes),
            "methods": index.methods,
            "edges": len(index.graph),
            "boundary_calls": len(index.boundary),
            "graph_nodes": len(index.graph),
            "internal_calls": sum(len(targets) for targets in index.graph.edges.values()),
            "reachability_max_depth": self._max_depth,
            "reachability_max_nodes": self._max_nodes,
            "truncated": index.truncated,
            "complete": index.complete,
            "dex_coverage": [item.describe() for item in index.dex_coverage],
            "data_flow_scope": "intra-procedural-selected-families",
            "data_flow_findings": [item.describe() for item in index.data_flows],
            "data_flow_methods": index.data_flow_methods,
            "data_flow_truncated_methods": index.data_flow_truncated_methods,
            "data_flow_complete": index.data_flow_complete,
            "data_flow_limitations": list(index.data_flow_limitations),
            "class_sources_sample": {name: list(index.class_sources.get(name, ())) for name in index.classes[:20]},
            "class_sample": list(index.classes[:20]),
        }
        return EvidenceService(self._session, self._store).record(
            investigation_id=investigation_id,
            kind=EvidenceKind.DEX_STRING,
            content=json.dumps(summary, indent=2).encode(),
            summary=(
                f"Call graph over {len(index.classes)} classes / {index.methods} methods "
                f"({len(index.graph)} graph nodes; coverage {'complete' if index.complete else 'partial'})"
            ),
            produced_by=AGENT,
        )

    def candidates(self, investigation_id: str) -> list[FrontierEntryRow]:
        return (
            self._session.query(FrontierEntryRow)
            .filter(
                FrontierEntryRow.investigation_id == investigation_id,
                FrontierEntryRow.state == "queued",
            )
            .order_by(FrontierEntryRow.inserted_at.asc(), FrontierEntryRow.id.asc())
            .all()
        )

    def investigate(
        self,
        investigation_id: str,
        entry: FrontierEntryRow,
        index: CodeIndex,
        manifest_evidence_id: str,
    ) -> dict[str, object] | None:
        component = (entry.action_args or {}).get("component")
        if not component:
            return None

        kind, exported, permission = self._component_facts(investigation_id, component)
        # Matched by name, not by signature: a real onReceive has parameters (RL-006).
        roots = tuple(
            method
            for name in entry_methods_for(kind)
            for method in index.graph.methods_named(component, name)
        )
        result = analyse(
            index.graph,
            entry_points=roots,
            boundary=index.boundary,
            max_depth=self._max_depth,
            max_nodes=self._max_nodes,
        )
        # An incomplete graph cannot support "no sink exists", however clean the search.
        if not index.complete and result.status == "not-reached":
            # A failed/skipped DEX or method-budget cut means absence is not established.
            result = ReachabilityResult(status="truncated", visited=result.visited)

        attributes: dict[str, object] = {"exported": exported, "permission": permission}
        attributes.update(result.attributes())
        if not index.complete and attributes.get("caller_check_absent") is not None:
            # A found path proves its own methods, and guards on it are visible. What a
            # truncated index cannot rule out is a check in a caller that never made it into
            # the graph, so "no caller check" stops being established. Found by a NEXUS test
            # that an incomplete index still produced a confirmed finding.
            attributes["caller_check_absent"] = None

        observation = self._record_observation(
            investigation_id, component, kind, result, index, manifest_evidence_id
        )

        finding, verdict = self._validator.validate(
            investigation_id=investigation_id,
            category="exported-component-no-permission",
            attributes=attributes,
            title=self._title(kind, component, result),
            description=result.explain(),
            evidence_refs=(manifest_evidence_id,),
            discovered_by=AGENT,
            validated_by="VERITAS",
            component_ref=component,
            confidence_cap=_CONFIDENCE[_bucket(result)],
        )
        return {
            "component": component,
            "kind": kind,
            "status": finding.status.value,
            "finding_id": finding.id,
            "verdict": verdict.verdict.value,
            "rejection_reason": verdict.rejection_reason.value if verdict.rejection_reason else None,
            "reachability": result.status,
            "sink": result.sink.id if result.sink else None,
            "guards": [g.id for g in result.guards],
            # None, not 0: a zero-length path would read as "the entry point is the sink".
            "path_length": len(result.path) if result.path else None,
            "method_path": [
                {"class_name": method.class_name, "name": method.name, "descriptor": method.descriptor}
                for method in result.path
            ],
            "maswe": list(result.sink.maswe) if result.sink else [],
            "data_flows": [
                item.describe() for item in index.data_flows
                if item.method.class_name == component
            ][:100],
            "data_flow_complete": index.data_flow_complete,
            "data_flow_limitations": list(index.data_flow_limitations)[:20],
            "explanation": result.explain(),
            "observation_id": observation.id,
            "attributes": attributes,
        }

    def inspect_callers(
        self,
        investigation_id: str,
        entry: FrontierEntryRow,
        index: CodeIndex,
        evidence_id: str,
    ) -> dict[str, object]:
        """Record direct bytecode callers for a typed method reference; do not create a finding."""
        args = entry.action_args or {}
        target = MethodRef(
            class_name=str(args["target_class"]),
            name=str(args["target_method"]),
            descriptor=str(args.get("target_descriptor") or ""),
        )
        if target not in index.graph.edges:
            # A method absent from the indexed graph is not proof that it has no callers.
            # The explicit exhaustive bit is false whenever the method or index is incomplete.
            exhaustive = bool(index.complete)
            callers: tuple[MethodRef, ...] = ()
            target_present = False
        else:
            callers = index.graph.callers_of(target)
            exhaustive = bool(index.complete)
            target_present = True

        observation = ObservationRow(
            id=new_id(IdPrefix.OBSERVATION),
            investigation_id=investigation_id,
            agent=AGENT,
            kind=ObservationKind.FACT.value,
            fidelity=Fidelity.DECOMPILED.value,
            subject_type="method",
            subject_ref=str(target),
            statement=(
                f"Indexed {len(callers)} direct application caller(s) for {target}"
                if target_present
                else f"Method {target} was not present in the indexed application call graph"
            ),
            attributes={
                "target_method": str(target),
                "target_present": target_present,
                "callers": [str(method) for method in callers],
                "caller_count": len(callers),
                "exhaustive": exhaustive,
                "index_truncated": index.truncated,
            },
            maswe=[],
            confidence=1.0 if target_present else 0.5,
            evidence_refs=[evidence_id],
            created_at=utcnow(),
        )
        self._session.add(observation)
        self._session.flush()
        return {
            "status": "observed",
            "target_method": str(target),
            "callers": [str(method) for method in callers],
            "caller_count": len(callers),
            "exhaustive": exhaustive,
            "observation_id": observation.id,
        }

    @staticmethod
    def _title(kind: str, component: str, result: ReachabilityResult) -> str:
        """The title must match the verdict: a refuted search is not an unfinished one.

        "reachability not established" was written for every non-reaching result, so a
        finding that had *decisively* established "no sink is reachable" was titled as if
        the question were still open.
        """
        short = component.rsplit(".", 1)[-1]
        if result.reached:
            return f"Exported {kind} {short} reaches a sensitive sink"
        if result.status == "not-reached":
            return (
                f"Exported {kind} {short} — no catalogued sink found on direct calls "
                "(bounded search, not determined)"
            )
        return f"Exported {kind} {short} — reachability not established"

    def _component_facts(self, investigation_id: str, component: str) -> tuple[str, bool, str | None]:
        observation = (
            self._session.query(ObservationRow)
            .filter(
                ObservationRow.investigation_id == investigation_id,
                ObservationRow.subject_type == "component",
                ObservationRow.subject_ref == component,
            )
            .first()
        )
        if observation is None:
            # The component was queued without an observation, which RECON never does.
            return "activity", True, None
        attributes = observation.attributes or {}
        return (
            str(attributes.get("kind", "activity")),
            bool(attributes.get("exported", True)),
            attributes.get("permission"),
        )

    def _record_observation(
        self,
        investigation_id: str,
        component: str,
        kind: str,
        result: ReachabilityResult,
        index: CodeIndex,
        manifest_evidence_id: str,
    ) -> ObservationRow:
        bucket = _bucket(result)

        row = ObservationRow(
            id=new_id(IdPrefix.OBSERVATION),
            investigation_id=investigation_id,
            agent=AGENT,
            # An inference, not a fact: the graph shows a call path exists in bytecode; it
            # does not show the path executes, or that the data on it is attacker-controlled.
            kind=ObservationKind.INFERENCE.value,
            fidelity=Fidelity.DECOMPILED.value,
            subject_type="component",
            subject_ref=component,
            statement=result.explain(),
            attributes={
                "reachability": result.status,
                "sink": result.sink.id if result.sink else None,
                "guards": [g.id for g in result.guards],
                "path": [str(m) for m in result.path],
                "visited": result.visited,
                "exhaustive": result.exhaustive,
                "index_truncated": index.truncated,
            },
            maswe=list(result.sink.maswe) if result.sink else [],
            confidence=_CONFIDENCE[bucket],
            evidence_refs=[manifest_evidence_id],
            created_at=utcnow(),
        )
        self._session.add(row)
        self._session.flush()
        return row

    def _advance(self, row: InvestigationRow, target: InvestigationState) -> None:
        advance(self._session, row, target, actor="NEXUS")
