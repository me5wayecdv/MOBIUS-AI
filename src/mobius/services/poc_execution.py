"""Persist reproducible PoC plans, results and evidence (D-042)."""
from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, replace
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

    def __init__(self, session: Session, artifact_store, *, native_adapter=None) -> None:
        self.session = session
        self.artifact_store = artifact_store
        self.native_adapter = native_adapter

    def execute_and_persist(self, plan: PoCTestPlan) -> PersistedPoCExecution:
        cancel_event = Event()
        with _CANCEL_LOCK:
            if plan.id in _CANCEL_EVENTS:
                raise RuntimeError("a PoC execution with this plan ID is already running")
            _CANCEL_EVENTS[plan.id] = cancel_event
        native_output = None
        try:
            from .phantom import adapter_from_env
            if plan.target_kind == "native_local_fixture":
                result, native_output = self._run_native(plan, cancel_event)
            else:
                result = SafePoCRunner(
                    self.session, emulator_adapter=adapter_from_env()
                ).run(plan, cancel_check=cancel_event.is_set)
        finally:
            with _CANCEL_LOCK:
                _CANCEL_EVENTS.pop(plan.id, None)
        input_json = plan.model_dump(mode="json")
        evidence = EvidenceService(self.session, self.artifact_store)
        native_evidence = []
        native_mapping = []
        if native_output is not None:
            for name, content in sorted(native_output.artifacts.items()):
                item = evidence.record(
                    investigation_id=plan.investigation_id,
                    kind=EvidenceKind.HTTP if name == "initial.native" else EvidenceKind.TOOL_OUTPUT,
                    content=content,
                    summary=(f"Native local fixture {name}; plan {plan.id}; anchor {plan.target_sha256}; "
                             "stdlib-loopback traffic, NOT APK traffic"),
                    produced_by="NATIVE_LOCAL",
                )
                native_evidence.append(item)
                native_mapping.append({"name":name,"evidence_id":item.id,"sha256":item.sha256,"bytes":item.byte_size})
            result=replace(result, output_json={**result.output_json,"native_artifacts":native_mapping})
            approved_total=sum(len(value) for value in native_output.artifacts.values())
            metadata_size=len(json.dumps(asdict(result),sort_keys=True,separators=(",",":"),default=str).encode())
            if approved_total+metadata_size>plan.max_output_bytes:
                raise ValueError("total native artifacts plus result metadata exceed approved output budget")
        output_json = asdict(result)
        input_bytes = json.dumps(input_json, sort_keys=True, separators=(",", ":")).encode()
        output_bytes = json.dumps(output_json, sort_keys=True, separators=(",", ":"), default=str).encode()
        log_text = "\n".join(
            f"[{step.index}] {step.action} {step.target_ref}: {step.status} "
            f"tool={step.tool_name}/{step.tool_version} duration_ms={step.duration_ms}"
            for step in result.steps
        ).encode("utf-8")
        if native_output is not None and (
            sum(len(v) for v in native_output.artifacts.values())+len(input_bytes)+len(output_bytes)+len(log_text)
            >plan.max_output_bytes
        ):
            raise ValueError("total native artifacts/plan/result/log bytes exceed approved output budget")
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
        for item in native_evidence:
            if item.id not in {plan_evidence.id, result_evidence.id, log_evidence.id}:
                self.session.merge(PoCRunEvidenceRow(
                    investigation_id=plan.investigation_id, run_id=run_id,
                    evidence_id=item.id, kind="native-local",
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
                "evidence_ids": list(dict.fromkeys([plan_evidence.id, result_evidence.id, log_evidence.id] + [e.id for e in native_evidence])),
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
            evidence_ids=tuple(dict.fromkeys([plan_evidence.id, result_evidence.id, log_evidence.id] + [e.id for e in native_evidence])),
            result=result,
        )

    def _run_native(self, plan, cancel_event):
        from .native_local_fixture import NativeFixtureRequest, NativeLocalFixtureAdapter, TRAFFIC_SOURCE
        from .poc_runner import PoCAdapterUnavailable, PoCExecutionError, PoCStepResult
        import time
        SafePoCRunner(self.session).validate_authority(plan)
        if self.native_adapter is None:
            raise PoCAdapterUnavailable("native local host adapter is disabled by default")
        if cancel_event.is_set():raise PoCExecutionError("cancelled before native host launch")
        request = NativeFixtureRequest.from_plan(plan)
        started, clock = utcnow(), time.monotonic()
        output = self.native_adapter.execute(request,cancel_check=cancel_event.is_set)
        # Revalidate authority after the bounded external leg before accepting
        # evidence. Expired/revoked/rebound cases cannot be promoted into pass.
        # Independent session/transaction avoids stale identity-map objects and
        # long-lived read snapshots. Caller must have committed authority before
        # execution; this seam never creates/auto-grants it.
        with Session(bind=self.session.get_bind()) as fresh_authority:
            SafePoCRunner(fresh_authority).validate_authority(plan)
        NativeLocalFixtureAdapter.validate(request, output)
        duration = max(0,int((time.monotonic()-clock)*1000))
        if output.status == "passed" and (cancel_event.is_set() or duration > request.total_seconds*1000):
            raise PoCExecutionError("native host cancelled or exceeded approved total duration")
        manifest = [{"name":name,"sha256":hashlib.sha256(content).hexdigest(),"bytes":len(content)}
                    for name,content in sorted(output.artifacts.items())]
        binding = asdict(request)
        payload = {"binding":binding,"traffic_source":TRAFFIC_SOURCE,
                   "anchor_is_not_traffic_source":True,"native_artifacts":manifest,
                   "tls_negative_controls":"UNTESTED","simulation_only":False,
                   "apk_execution":False,"profile":request.profile,"host_status":output.status,
                   "host_failure_code":output.failure_code}
        if sum(len(value) for value in output.artifacts.values())>plan.max_output_bytes:
            raise PoCExecutionError("native original artifacts exceed approved total output budget")
        encoded=json.dumps(payload,sort_keys=True).encode()
        if len(encoded)>plan.max_output_bytes:raise PoCExecutionError("native result metadata exceeds budget")
        step=PoCStepResult(0,"capture_native_local_fixture_v1",request.profile,
            output.status,output.status=="passed",output.status=="passed",None,duration,"native-local",self.native_adapter.VERSION,
            "Actual controlled loopback capture/request replay, not APK traffic")
        result=PoCExecutionResult(plan.id,plan.investigation_id,plan.target_sha256,
            output.status,started,utcnow(),duration,(step,),payload,output.tool_versions,
            ("Controlled stdlib local traffic only; no APK runtime or Android claim",
             "TLS rejection controls untested in positive profile",
             "Host lifecycle timeout/cancellation paths require separate evidence"),
            ({"action":"stop_native_local_fixture","status":"completed" if output.status=="passed" else "inspect_failure_evidence",
              "detail":("validated original driver/wrapper/emergency cleanup evidence" if output.status=="passed" else "failed host diagnostics retained, no cleanup success inferred")},))
        return result,output

    def get(self, run_id: str) -> PoCRunRow:
        row = self.session.get(PoCRunRow, run_id)
        if row is None:
            raise LookupError(f"PoC run {run_id} not found")
        return row

    def readback(self, run_id: str, *, investigation_id: str) -> dict[str, Any]:
        """Read stored rows/original bytes, never regenerate fixture evidence."""
        from ..adapters.models import EvidenceRow
        row=self.get(run_id)
        if row.investigation_id!=investigation_id:raise LookupError("PoC run not in investigation")
        references=[]
        for link in self.evidence_for(run_id):
            evidence=self.session.get(EvidenceRow,link["evidence_id"])
            if evidence is None or evidence.investigation_id!=investigation_id:
                raise ValueError("cross-investigation or absent PoC evidence")
            content=self.artifact_store.get(evidence.object_key)
            digest=hashlib.sha256(content).hexdigest()
            if digest!=evidence.sha256 or len(content)!=evidence.byte_size:
                raise ValueError("persisted PoC evidence differs from original digest")
            references.append({**link,"sha256":digest,"bytes":len(content)})
        encoded=lambda value:json.dumps(value,sort_keys=True,separators=(",", ":"),default=str).encode()
        if hashlib.sha256(encoded(row.input_json)).hexdigest()!=row.input_sha256:
            raise ValueError("persisted input hash mismatch")
        if hashlib.sha256(encoded(row.output_json)).hexdigest()!=row.output_sha256:
            raise ValueError("persisted output hash mismatch")
        by_kind={item["kind"]:item for item in references if item["kind"] in {"plan","result","log"}}
        if set(by_kind)!={"plan","result","log"}:raise ValueError("required PoC plan/result/log links absent")
        def linked_bytes(item):
            return self.artifact_store.get(self.session.get(EvidenceRow,item["evidence_id"]).object_key)
        if hashlib.sha256(linked_bytes(by_kind["plan"])).hexdigest()!=row.input_sha256:
            raise ValueError("linked plan bytes differ from run input")
        if hashlib.sha256(linked_bytes(by_kind["result"])).hexdigest()!=row.output_sha256:
            raise ValueError("linked result bytes differ from run output")
        if (row.input_json.get("id")!=row.plan_id or row.input_json.get("investigation_id")!=investigation_id
            or row.input_json.get("target_sha256")!=row.target_sha256
            or row.input_json.get("authorization_id")!=row.authorization_id
            or row.input_json.get("approval_id")!=row.approval_id):
            raise ValueError("run/plan/case/target binding mismatch")
        if row.input_json.get("target_kind")=="native_local_fixture":
            from .native_local_fixture import REQUIRED, NativeFixtureRequest, NativeFixtureOutput, NativeLocalFixtureAdapter
            payload=row.output_json["output_json"]
            manifest=payload["native_artifacts"]
            if len({x["name"] for x in manifest})!=len(manifest):raise ValueError("duplicate native artifact name")
            mapping={x["name"]:x for x in manifest}
            if row.status=="passed" and not REQUIRED<=mapping.keys():raise ValueError("required native artifact mapping missing")
            native_refs={x["evidence_id"]:x for x in references if x["kind"]=="native-local"}
            if {x["evidence_id"] for x in manifest}!=set(native_refs):raise ValueError("native links incomplete/substituted")
            files={}
            for name,item in mapping.items():
                ref=native_refs[item["evidence_id"]]
                if ref["sha256"]!=item["sha256"] or ref["bytes"]!=item["bytes"]:
                    raise ValueError("native artifact evidence mapping changed")
                files[name]=linked_bytes(ref)
            request=NativeFixtureRequest(**payload["binding"])
            if (request.plan_id!=row.plan_id or request.investigation_id!=investigation_id
                or request.authorization_id!=row.authorization_id or request.approval_id!=row.approval_id
                or request.anchor_apk_sha256!=row.target_sha256
                or request.anchor_package!=row.input_json["target_package"]):
                raise ValueError("native host binding differs from persisted plan/run")
            expected_plan=hashlib.sha256(encoded({k:v for k,v in row.input_json.items() if k!="approval_id"})).hexdigest()
            if request.plan_sha256!=expected_plan:raise ValueError("native approved plan digest mismatch")
            NativeLocalFixtureAdapter.validate(request,NativeFixtureOutput(request,files,tuple(row.tool_versions),
                payload.get("host_status","passed"),payload.get("host_failure_code")))
        return {"run_id":row.id,"plan_id":row.plan_id,"investigation_id":investigation_id,
                "authorization_id":row.authorization_id,"approval_id":row.approval_id,
                "anchor_apk_sha256":row.target_sha256,"status":row.status,
                "input_sha256":row.input_sha256,"output_sha256":row.output_sha256,
                "evidence":references,"output":row.output_json}

    def evidence_for(self, run_id: str) -> list[dict[str, Any]]:
        row = self.get(run_id)
        links = self.session.execute(
            select(PoCRunEvidenceRow).where(
                PoCRunEvidenceRow.investigation_id == row.investigation_id,
                PoCRunEvidenceRow.run_id == run_id,
            ).order_by(PoCRunEvidenceRow.kind)
        ).scalars()
        return [{"evidence_id": link.evidence_id, "kind": link.kind} for link in links]
