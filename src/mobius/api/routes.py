"""HTTP routes. Every handler is a thin translation between HTTP and a service."""

from __future__ import annotations

import asyncio
import json
import os
import re

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request, UploadFile
from fastapi.responses import JSONResponse, PlainTextResponse, StreamingResponse

from ..adapters.events import SqlEventStore, utcnow
from ..adapters.models import ApplicationRow, AuthorizationRow, DecisionRow, EvidenceRow, FindingRow, HypothesisRow, InvestigationRow, WorkerJobRow, PoCRunRow
from ..core import fsm, gates
from ..core.enums import EvidenceKind, InvestigationState, RejectionReason
from ..services.evidence import EvidenceService
from ..services.intake import IntakeService, MAX_APK_BYTES
from ..services.archivist import ArchivistService
from ..services.nexus import NexusService
from ..services.recon import ReconService
from ..services.spectre import SpectreService
from ..services.validation import ValidationService
from ..services.worker_queue import WorkerQueue
from ..core.schemas import PoCTestPlan
from ..services.poc_approval import PoCApprovalService
from ..services.poc_execution import PoCExecutionService, request_poc_cancel
from .deps import analyst_id, get_context
from .schemas import (
    AuthorizationCreate,
    PauseRequest,
    ScanCreate,
    ValidationRequest,
    ModelConsentRequest,
    PoCApprovalRequest,
    PoCApprovalDecision,
)

router = APIRouter()


def _session():
    ctx = get_context()
    session = ctx.session()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


# Function scope: the commit must land before the response is sent. The default
# ("request") scope runs teardown after the response, which let a follow-up
# GET /scans read before the POST /scans commit was visible (War Room E2E flake:
# the investigation list came back empty right after creation).
SessionDep = Depends(_session, scope="function")


def _require_scan_owner(session, scan_id: str, who: str) -> InvestigationRow:
    """Hide investigations owned by another identity behind the same 404 as missing IDs.

    This is an authorization seam, not authentication: analyst_id is still a development
    stub and production startup remains blocked until a verified identity provider exists.
    """
    row = session.get(InvestigationRow, scan_id)
    if row is None or row.created_by != who:
        from ..services.errors import NotFound

        raise NotFound(f"investigation {scan_id} not found")
    return row


# ------------------------------------------------------------------------------------
# System
# ------------------------------------------------------------------------------------


@router.get("/health", tags=["system"])
def health() -> dict[str, object]:
    ctx = get_context()
    from sqlalchemy import text

    with ctx.session() as session:
        session.execute(text("SELECT 1"))
    return {
        "status": "ok",
        "env": ctx.settings.env,
        # Capability is reported BEFORE a scan starts, so the user never waits 20 minutes
        # to discover a tool was missing (NFR-PORT-1).
        "tools": {
            "androguard": _module_available("androguard"),
            "jadx": _which("jadx"),
            "apktool": _which("apktool"),
            "adb": _which("adb"),
        },
        "sandbox": "process (container runtime not detected)",
        "auth": "stub",
    }


def _module_available(name: str) -> bool:
    import importlib.util

    return importlib.util.find_spec(name) is not None


def _which(binary: str) -> bool:
    import shutil

    return shutil.which(binary) is not None


@router.get("/gates", tags=["system"])
def list_gates() -> list[dict[str, object]]:
    """The confirmation gates, so a client can show required evidence before a scan."""
    return [
        {
            "category": g.category,
            "title": g.title,
            "maswe": list(g.maswe),
            "masvs": list(g.masvs),
            "severity_hint": g.severity_hint.value,
            "required_evidence": list(g.required_evidence()),
            "clauses": [{"key": c.key, "description": c.description} for c in g.clauses],
        }
        for g in gates.GATES.values()
    ]


# ------------------------------------------------------------------------------------
# Applications and authorisations
# ------------------------------------------------------------------------------------


@router.post("/applications", status_code=201, tags=["applications"])
async def upload_application(
    file: UploadFile,
    force: bool = Query(default=False),
    session=SessionDep,
    who: str = Depends(analyst_id),
):
    ctx = get_context()
    # Bound memory use before the service validates the archive. Reading without a limit
    # lets a client force an arbitrarily large allocation before MAX_APK_BYTES is checked.
    data = await file.read(MAX_APK_BYTES + 1)
    await file.close()
    service = IntakeService(session, ctx.store)
    app, created = service.create_application(data, file.filename or "", uploaded_by=who)
    body = _app_body(app)
    if not created and not force:
        body["duplicate"] = True
    return JSONResponse(status_code=201, content=body)


@router.post("/authorizations", status_code=201, tags=["authorizations"])
def create_authorization(
    payload: AuthorizationCreate,
    session=SessionDep,
    who: str = Depends(analyst_id),
):
    ctx = get_context()
    service = IntakeService(session, ctx.store)
    auth = service.create_authorization(
        apk_sha256=payload.apk_sha256,
        target_package=payload.target_package,
        scope_text=payload.scope_text,
        statement=payload.statement,
        max_intensity=payload.max_intensity,
        granted_by=who,
        expires_at=payload.expires_at,
    )
    return {
        "id": auth.id,
        "apk_sha256": auth.apk_sha256,
        "target_package": auth.target_package,
        "max_intensity": auth.max_intensity,
        "expires_at": auth.expires_at,
    }


# ------------------------------------------------------------------------------------
# Scans
# ------------------------------------------------------------------------------------


@router.post("/scans", status_code=201, tags=["scans"])
def create_scan(
    payload: ScanCreate,
    session=SessionDep,
    who: str = Depends(analyst_id),
):
    if payload.llm_data_sharing:
        raise HTTPException(
            status_code=422,
            detail="model consent must be granted explicitly after scan creation via PUT /scans/{scan_id}/model-consent with provider=ollama",
        )
    ctx = get_context()
    from ..core.schemas import Budget

    service = IntakeService(session, ctx.store)
    inv = service.create_investigation(
        application_id=payload.application_id,
        authorization_id=payload.authorization_id,
        objective=payload.objective,
        intensity=payload.intensity,
        created_by=who,
        budget=Budget(**payload.budget.model_dump()),
    )
    service.start(inv.id)
    return _scan_body(session, inv.id)


@router.get("/scans", tags=["scans"])
def list_scans(limit: int = Query(default=50, ge=1, le=200), session=SessionDep, who: str = Depends(analyst_id)):
    """Investigations, newest first.

    Exists because a UI cannot show a scan it cannot list, and because the alternative -
    guessing an id - is how a demo grows a hardcoded one.
    """
    rows = (
        session.query(InvestigationRow)
        .filter(InvestigationRow.created_by == who)
        .order_by(InvestigationRow.created_at.desc(), InvestigationRow.id.desc())
        .limit(limit)
        .all()
    )
    return {
        "items": [
            {
                "id": row.id,
                "state": row.state,
                "objective": row.objective,
                "intensity": row.intensity,
                "stop_reason": row.stop_reason,
                "application_id": row.application_id,
                "created_at": row.created_at,
            }
            for row in rows
        ],
        "count": len(rows),
    }


@router.get("/scans/{scan_id}", tags=["scans"])
def get_scan(scan_id: str, session=SessionDep, who: str = Depends(analyst_id)):
    _require_scan_owner(session, scan_id, who)
    return _scan_body(session, scan_id)


@router.post("/scans/{scan_id}/pause", tags=["scans"])
def pause_scan(
    scan_id: str, payload: PauseRequest | None = None, session=SessionDep, who: str = Depends(analyst_id)
):
    _require_scan_owner(session, scan_id, who)
    ctx = get_context()
    IntakeService(session, ctx.store).pause(scan_id, by=who, reason=(payload.reason if payload else None))
    return _scan_body(session, scan_id)


@router.post("/scans/{scan_id}/resume", tags=["scans"])
def resume_scan(scan_id: str, session=SessionDep, who: str = Depends(analyst_id)):
    _require_scan_owner(session, scan_id, who)
    ctx = get_context()
    IntakeService(session, ctx.store).resume(scan_id, by=who)
    return _scan_body(session, scan_id)


@router.post("/scans/{scan_id}/cancel", tags=["scans"])
def cancel_scan(scan_id: str, session=SessionDep, who: str = Depends(analyst_id)):
    _require_scan_owner(session, scan_id, who)
    ctx = get_context()
    IntakeService(session, ctx.store).cancel(scan_id, by=who)
    return _scan_body(session, scan_id)


@router.get("/scans/{scan_id}/events", tags=["scans"])
def get_events(
    scan_id: str,
    after: int = Query(default=0, ge=0),
    limit: int = Query(default=200, ge=1, le=1000),
    session=SessionDep,
    who: str = Depends(analyst_id),
):
    _require_scan_owner(session, scan_id, who)
    store = SqlEventStore(session)
    events = store.read_after(scan_id, after_seq=after, limit=limit)
    return {
        "items": [
            {
                "seq": e.seq,
                "type": e.type,
                "payload": e.payload,
                "actor": e.actor,
                "causation_id": e.causation_id,
                "correlation_id": e.correlation_id,
                "at": e.created_at,
            }
            for e in events
        ],
        "current_seq": store.current_seq(scan_id),
        "next_after": events[-1].seq if events else after,
    }


@router.get("/scans/{scan_id}/findings", tags=["scans"])
def get_findings(scan_id: str, session=SessionDep, who: str = Depends(analyst_id)):
    _require_scan_owner(session, scan_id, who)
    rows = (
        session.query(FindingRow)
        .filter(FindingRow.investigation_id == scan_id)
        .order_by(FindingRow.created_at.asc())
        .all()
    )
    return {
        "items": [
            {
                "id": r.id,
                "title": r.title,
                "category": r.category,
                "severity": r.severity,
                "confidence": r.confidence,
                "status": r.status,
                "maswe": r.maswe,
                "masvs": r.masvs,
                "evidence_refs": r.evidence_refs,
                "discovered_by": r.discovered_by,
                "validated_by": r.validated_by,
                "gate_evidence": r.gate_evidence,
            }
            for r in rows
        ]
    }



@router.get("/scans/{scan_id}/hypotheses", tags=["scans"])
def get_hypotheses(scan_id: str, session=SessionDep, who: str = Depends(analyst_id)):
    _require_scan_owner(session, scan_id, who)
    rows = session.query(HypothesisRow).filter(
        HypothesisRow.investigation_id == scan_id
    ).order_by(HypothesisRow.priority.desc(), HypothesisRow.created_at.asc()).all()
    return {"items": [{
        "id": row.id, "claim": row.claim, "maswe": row.maswe,
        "derived_from": row.derived_from, "required_evidence": row.required_evidence,
        "satisfied_evidence": row.satisfied_evidence, "status": row.status,
        "priority": row.priority, "depth": row.depth, "parent_id": row.parent_id,
    } for row in rows]}


@router.get("/scans/{scan_id}/evidence", tags=["scans"])
def get_evidence(scan_id: str, session=SessionDep, who: str = Depends(analyst_id)):
    _require_scan_owner(session, scan_id, who)
    ctx = get_context()
    items = EvidenceService(session, ctx.store).list_for(scan_id)
    return {
        "items": [
            {
                "id": e.id,
                "kind": e.kind.value,
                "sha256": e.sha256,
                "byte_size": e.byte_size,
                "summary": e.summary,
                "produced_by": e.produced_by,
            }
            for e in items
        ]
    }


@router.put("/scans/{scan_id}/model-consent", tags=["scans"])
def set_model_consent(
    scan_id: str,
    payload: ModelConsentRequest,
    session=SessionDep,
    who: str = Depends(analyst_id),
):
    """Record explicit, revocable per-investigation consent for local model processing."""
    scan = _require_scan_owner(session, scan_id, who)
    if payload.enabled and payload.provider != "ollama":
        from ..services.errors import ScanStateConflict
        raise ScanStateConflict("enabled model consent must explicitly name the local ollama provider")
    if not payload.enabled and payload.provider is not None:
        from ..services.errors import ScanStateConflict
        raise ScanStateConflict("disabled model consent must not name a provider")
    scan.llm_data_sharing = {
        "enabled": payload.enabled,
        "provider": payload.provider if payload.enabled else None,
    }
    SqlEventStore(session).emit(
        scan_id,
        "model_consent_updated",
        {"enabled": payload.enabled, "provider": payload.provider if payload.enabled else None},
        actor=who,
    )
    return {"investigation_id": scan_id, "llm_data_sharing": scan.llm_data_sharing}


@router.get("/nexus/actions", tags=["nexus"])
def list_nexus_actions():
    """Expose the closed, server-owned action registry for client inspection."""
    from ..core.actions import ActionRegistry

    return {"items": ActionRegistry().describe()}


@router.post("/scans/{scan_id}/nexus/hypotheses", tags=["nexus"])
def generate_nexus_hypotheses(
    scan_id: str,
    component: str | None = Query(default=None, max_length=500),
    session=SessionDep,
    who: str = Depends(analyst_id),
):
    """Generate testable hypotheses; model use is consent-gated and budgeted cumulatively."""
    _require_scan_owner(session, scan_id, who)
    ctx = get_context()
    from ..services.nexus_hypotheses import NexusHypothesisService

    return NexusHypothesisService(
        session,
        gateway=ctx.model_gateway,
        session_factory=ctx.session_factory,
        store=ctx.store,
    ).generate(scan_id, component=component)


@router.get("/scans/{scan_id}/decisions", tags=["scans"])
def get_decisions(
    scan_id: str,
    after: str | None = Query(default=None, max_length=40),
    session=SessionDep,
    who: str = Depends(analyst_id),
):
    """Replay the investigation's persisted decision provenance (D-025).

    Every decision row, including rejected alternatives and full model
    provenance, in creation order. `after` returns only rows created after
    the given DecisionRow id (cursor over creation order).
    """
    _require_scan_owner(session, scan_id, who)
    rows = session.query(DecisionRow).filter(
        DecisionRow.investigation_id == scan_id
    ).order_by(DecisionRow.created_at.asc(), DecisionRow.id.asc()).all()
    if after is not None:
        seen = False
        kept = []
        for row in rows:
            if seen:
                kept.append(row)
            elif row.id == after:
                seen = True
        rows = kept
    return {"items": [{
        "id": row.id,
        "agent": row.agent,
        "action": row.action,
        "action_args": row.action_args,
        "considered_evidence": row.considered_evidence,
        "alternatives": row.alternatives,
        "expected_outcome": row.expected_outcome,
        "uncertainty": row.uncertainty,
        "prompt_version": row.prompt_version,
        "model_id": row.model_id,
        "provider": row.provider,
        "model_role": row.model_role,
        "requested_model": row.requested_model,
        "system_prompt_sha256": row.system_prompt_sha256,
        "input_sha256": row.input_sha256,
        "schema_sha256": row.schema_sha256,
        "response_sha256": row.response_sha256,
        "schema_name": row.schema_name,
        "output_json": row.output_json,
        "input_tokens": row.input_tokens,
        "output_tokens": row.output_tokens,
        "latency_ms": row.latency_ms,
        "temperature": row.temperature,
        "max_tokens": row.max_tokens,
        "created_at": row.created_at,
    } for row in rows]}


@router.post("/scans/{scan_id}/findings/{finding_id}/veritas-review", tags=["nexus"])
def run_veritas_review(
    scan_id: str,
    finding_id: str,
    producer_model_id: str = Query(min_length=1, max_length=120),
    session=SessionDep,
    who: str = Depends(analyst_id),
):
    """Run the advisory VERITAS challenge against one finding (D-026).

    Consent-gated and budgeted like every model path; the review is advisory
    only - deterministic gates remain the sole verdict authority.
    """
    _require_scan_owner(session, scan_id, who)
    from ..services.errors import ModelConsentRequiredError, ModelOutputInvalidError, NotFound
    from ..services.model_provider import ModelConsentRequired, ModelOutputInvalid
    from ..services.veritas import VeritasReviewService

    finding = session.get(FindingRow, finding_id)
    if finding is None or finding.investigation_id != scan_id:
        raise NotFound(f"finding {finding_id} not found in this investigation")
    ctx = get_context()
    try:
        return VeritasReviewService(
            session,
            gateway=ctx.model_gateway,
            session_factory=ctx.session_factory,
        ).review(finding_id, producer_model_id=producer_model_id)
    except ModelConsentRequired as exc:
        raise ModelConsentRequiredError(str(exc)) from exc
    except (ModelOutputInvalid, ValueError) as exc:
        raise ModelOutputInvalidError(str(exc)) from exc


def _jadx_lookup(session):
    """Build a fail-closed lookup over the configured per-artifact JADX cache."""
    from ..services.code_lookup import JadxCodeLookup
    from ..services.tool_runner import ToolRunner
    from ..adapters.jadx import build_jadx_tool_spec

    ctx = get_context()
    runner = ToolRunner(
        workspace_root=ctx.settings.artifact_root / "tool-workspaces",
        backend=None,  # Until a verified digest-pinned OCI backend is registered, cache misses fail closed.
        tools=(build_jadx_tool_spec(),),
    )
    return JadxCodeLookup(
        session=session,
        store=ctx.store,
        cache_root=ctx.settings.jadx_cache_root or (ctx.settings.artifact_root / "jadx-cache"),
        runner=runner,
    )


def _jadx_http_error(exc):
    """Map lookup failures to stable HTTP errors without hiding tool/cache failures."""
    from ..adapters.jadx import JadxCacheError, JadxError, JadxExecutionFailed, JadxUnavailable

    if isinstance(exc, JadxUnavailable):
        raise HTTPException(status_code=503, detail={"code": "JADX_BACKEND_UNAVAILABLE", "detail": exc.detail})
    if isinstance(exc, JadxCacheError):
        raise HTTPException(status_code=409, detail={"code": "JADX_CACHE_INVALID", "detail": exc.detail})
    if isinstance(exc, JadxExecutionFailed):
        raise HTTPException(status_code=422, detail={"code": "JADX_EXECUTION_FAILED", "detail": exc.detail})
    if isinstance(exc, JadxError):
        code = exc.status.upper().replace("-", "_")
        status = 404 if exc.status in {"source_unavailable", "class_not_found", "source_not_found", "method_not_found"} else (409 if exc.status == "method_ambiguous" else 422)
        raise HTTPException(status_code=status, detail={"code": f"JADX_{code}", "detail": exc.detail})
    raise exc


def _enqueue_jadx_job(scan_id: str, session, who: str):
    """Queue decompilation only when an immutable worker image is configured."""
    scan = _require_scan_owner(session, scan_id, who)
    ctx = get_context()
    application = session.get(ApplicationRow, scan.application_id)
    authorization = session.get(AuthorizationRow, scan.authorization_id) if scan.authorization_id else None
    if (
        application is None or authorization is None
        or authorization.apk_sha256 != application.sha256
        or authorization.revoked_at is not None
        or authorization.expires_at <= utcnow()
    ):
        raise HTTPException(status_code=409, detail={"code": "AUTHORIZATION_NOT_LIVE"})
    image = ctx.settings.jadx_image
    if not image or not re.fullmatch(r"[A-Za-z0-9./:_-]+@sha256:[0-9a-f]{64}", image):
        raise HTTPException(
            status_code=503,
            detail={"code": "JADX_WORKER_IMAGE_UNAVAILABLE", "detail": "Configure MOBIUS_JADX_IMAGE with an approved immutable SHA-256 image reference."},
        )
    job = WorkerQueue(session).enqueue_jadx_decompile(scan_id, application.artifact_key)
    SqlEventStore(session).emit(
        scan_id, "worker_job_queued",
        {"job_id": job.id, "kind": job.kind, "status": job.status},
        actor="M2",
    )
    return {
        "job_id": job.id,
        "investigation_id": scan_id,
        "kind": job.kind,
        "status": job.status,
        "created_at": job.created_at,
    }


@router.post("/scans/{scan_id}/code/decompile", status_code=202, tags=["code"])
def decompile_scan_code(
    scan_id: str,
    session=SessionDep,
    who: str = Depends(analyst_id),
):
    """Queue the authorized APK for isolated JADX decompilation."""
    return _enqueue_jadx_job(scan_id, session, who)


@router.post("/scans/{scan_id}/code/decompile/jobs", status_code=202, tags=["code"])
def enqueue_jadx_decompile(
    scan_id: str,
    session=SessionDep,
    who: str = Depends(analyst_id),
):
    """Explicit queued-job alias for clients that prefer a /jobs resource."""
    return _enqueue_jadx_job(scan_id, session, who)


@router.get("/scans/{scan_id}/code/decompile/jobs/{job_id}", tags=["code"])
def get_jadx_decompile_job(
    scan_id: str,
    job_id: str,
    session=SessionDep,
    who: str = Depends(analyst_id),
):
    _require_scan_owner(session, scan_id, who)
    job = WorkerQueue(session).get(job_id)
    if job.investigation_id != scan_id or job.kind != "jadx_decompile":
        from ..services.errors import NotFound
        raise NotFound(f"JADX worker job {job_id} not found")
    return {
        "job_id": job.id,
        "kind": job.kind,
        "status": job.status,
        "attempts": job.attempts,
        "worker_id": job.worker_id,
        "error_code": job.error_code,
        "error_detail": job.error_detail,
        "result": job.result_json if job.status == "succeeded" else None,
        "created_at": job.created_at,
        "started_at": job.started_at,
        "finished_at": job.finished_at,
    }


@router.get("/scans/{scan_id}/code/classes", tags=["code"])
def get_code_classes(
    scan_id: str,
    prefix: str | None = Query(default=None, max_length=300),
    limit: int = Query(default=200, ge=1, le=5000),
    session=SessionDep,
    who: str = Depends(analyst_id),
):
    _require_scan_owner(session, scan_id, who)
    try:
        return _jadx_lookup(session).classes(scan_id, prefix=prefix, limit=limit)
    except Exception as exc:
        _jadx_http_error(exc)


@router.get("/scans/{scan_id}/code/methods", tags=["code"])
def get_code_methods(
    scan_id: str,
    class_name: str = Query(min_length=1, max_length=500),
    limit: int = Query(default=200, ge=1, le=500),
    session=SessionDep,
    who: str = Depends(analyst_id),
):
    _require_scan_owner(session, scan_id, who)
    try:
        return _jadx_lookup(session).methods(scan_id, class_name=class_name, limit=limit)
    except Exception as exc:
        _jadx_http_error(exc)


@router.get("/scans/{scan_id}/code/source", tags=["code"])
def get_code_source(
    scan_id: str,
    path: str = Query(min_length=1, max_length=1000),
    start_line: int = Query(default=1, ge=1),
    end_line: int = Query(default=40, ge=1),
    session=SessionDep,
    who: str = Depends(analyst_id),
):
    _require_scan_owner(session, scan_id, who)
    try:
        return _jadx_lookup(session).source(
            scan_id, path=path, start_line=start_line, end_line=end_line
        )
    except Exception as exc:
        _jadx_http_error(exc)


@router.get("/scans/{scan_id}/coverage-manifest", tags=["scans"])
def get_coverage_manifest(
    scan_id: str,
    session=SessionDep,
    who: str = Depends(analyst_id),
):
    """Return the investigation's structured, evidence-backed code coverage manifest."""
    _require_scan_owner(session, scan_id, who)
    from ..services.coverage_manifest import CoverageManifestBuilder

    ctx = get_context()
    return CoverageManifestBuilder(session, ctx.store).build(scan_id)


@router.post("/scans/{scan_id}/code/source/evidence", status_code=201, tags=["code"])
def persist_code_source_evidence(
    scan_id: str,
    class_name: str = Query(min_length=1, max_length=500),
    method_name: str = Query(min_length=1, max_length=200),
    session=SessionDep,
    who: str = Depends(analyst_id),
):
    """Persist one bounded method excerpt from the verified JADX cache as immutable evidence."""
    _require_scan_owner(session, scan_id, who)
    try:
        from ..services.source_evidence import capture_method_source

        ctx = get_context()
        return capture_method_source(
            session=session,
            store=ctx.store,
            lookup=_jadx_lookup(session),
            investigation_id=scan_id,
            class_name=class_name,
            method_name=method_name,
        )
    except Exception as exc:
        _jadx_http_error(exc)


@router.get("/scans/{scan_id}/evidence-package", tags=["scans"])
def get_evidence_package(
    scan_id: str,
    component: str | None = Query(default=None, max_length=500),
    session=SessionDep,
    who: str = Depends(analyst_id),
):
    """Build bounded, targeted context from this investigation's persisted evidence."""
    _require_scan_owner(session, scan_id, who)
    from ..services.evidence_package import EvidencePackageBuilder

    ctx = get_context()
    return EvidencePackageBuilder(session, store=ctx.store).build(
        scan_id, component=component
    ).as_dict()




# ------------------------------------------------------------------------------------
# Attack graph (D-033)
# ------------------------------------------------------------------------------------


@router.post("/scans/{scan_id}/graph/rebuild", tags=["graph"])
def rebuild_attack_graph(scan_id: str, session=SessionDep, who: str = Depends(analyst_id)):
    """Rebuild the persisted evidence graph and candidate paths for one owned investigation."""
    _require_scan_owner(session, scan_id, who)
    from ..services.graph import GraphPersistenceService
    from ..services.graph_correlation import GraphCorrelationService
    from ..services.attack_paths import CandidateAttackPathService

    GraphPersistenceService(session).rebuild(scan_id)
    correlation = GraphCorrelationService(session).correlate(scan_id)
    paths = CandidateAttackPathService(session).build(scan_id)
    graph = GraphPersistenceService(session).get_graph(scan_id)
    SqlEventStore(session).emit(
        scan_id, "attack_graph_rebuilt",
        {"nodes": len(graph.nodes), "edges": len(graph.edges),
         "candidate_paths": len(paths.candidates),
         "data_source_observations": correlation.data_source_observations},
        actor="GRAPH",
    )
    return {"investigation_id": scan_id, "nodes": len(graph.nodes),
            "edges": len(graph.edges), "candidate_paths": len(paths.candidates),
            "limitations": list(paths.limitations)}


@router.get("/scans/{scan_id}/graph", tags=["graph"])
def get_attack_graph(scan_id: str, session=SessionDep, who: str = Depends(analyst_id)):
    """Read persisted graph nodes/edges in a React Flow-compatible shape."""
    _require_scan_owner(session, scan_id, who)
    from ..services.graph import GraphPersistenceService

    graph = GraphPersistenceService(session).get_graph(scan_id)
    nodes = [{
        "id": node.id, "type": "default", "position": {"x": 0, "y": 0},
        "data": {"label": node.label, "node_type": node.node_type, "ref": node.ref,
                 "assertion": node.assertion.value, "attributes": node.attributes,
                 "evidence_refs": list(node.evidence_refs)},
    } for node in graph.nodes]
    edges = [{
        "id": edge.id, "source": edge.source_id, "target": edge.target_id,
        "label": edge.relation, "type": "smoothstep",
        "data": {"relation": edge.relation, "assertion": edge.assertion.value,
                 "rationale": edge.rationale, "evidence_refs": list(edge.evidence_refs)},
    } for edge in graph.edges]
    candidate_paths = [{
        "id": node.id, "label": node.label, "ref": node.ref,
        **(node.attributes or {}), "evidence_refs": list(node.evidence_refs),
    } for node in graph.nodes if node.node_type == "candidate_path"]
    return {"investigation_id": graph.investigation_id, "nodes": nodes,
            "edges": edges, "candidate_paths": candidate_paths}

@router.post("/scans/{scan_id}/evidence", status_code=201, tags=["scans"])
def post_evidence(
    scan_id: str,
    kind: EvidenceKind,
    summary: str,
    content: str,
    session=SessionDep,
    who: str = Depends(analyst_id),
):
    _require_scan_owner(session, scan_id, who)
    ctx = get_context()
    ev = EvidenceService(session, ctx.store).record(
        investigation_id=scan_id,
        kind=kind,
        content=content.encode(),
        summary=summary,
        produced_by=who,
    )
    return {"id": ev.id, "sha256": ev.sha256, "byte_size": ev.byte_size}


@router.post("/scans/{scan_id}/validate", tags=["validation"])
def validate(
    scan_id: str,
    payload: ValidationRequest,
    session=SessionDep,
    who: str = Depends(analyst_id),
):
    _require_scan_owner(session, scan_id, who)
    """Evaluate a gate and record a finding plus its verdict.

    This endpoint is how the thesis is exercised end to end before the analysis agents
    exist: attributes in, gate evaluated, finding and verdict out.
    """
    service = ValidationService(session)
    reason = RejectionReason(payload.rejection_reason) if payload.rejection_reason else None
    finding, verdict = service.validate(
        investigation_id=scan_id,
        category=payload.category,
        attributes=payload.attributes,
        title=payload.title,
        description=payload.description,
        evidence_refs=payload.evidence_refs,
        discovered_by=payload.discovered_by,
        validated_by=payload.validated_by,
        component_ref=payload.component_ref,
        rejection_reason=reason,
    )
    return {
        "finding": {
            "id": finding.id,
            "status": finding.status.value,
            "severity": finding.severity.value,
            "confidence": finding.confidence,
            "gate_evidence": finding.gate_evidence,
        },
        "verdict": {
            "id": verdict.id,
            "verdict": verdict.verdict.value,
            "rejection_reason": verdict.rejection_reason.value if verdict.rejection_reason else None,
            "rationale": verdict.rationale,
            "gate_passed": verdict.gate_passed,
        },
    }


# ------------------------------------------------------------------------------------
# RECON
# ------------------------------------------------------------------------------------


@router.post("/scans/{scan_id}/recon", tags=["scans"])
def run_recon(scan_id: str, session=SessionDep, who: str = Depends(analyst_id)):
    _require_scan_owner(session, scan_id, who)
    """Run the deterministic manifest analysis. Idempotent only in the sense that it
    refuses to run twice: re-running would duplicate observations and frontier entries."""
    ctx = get_context()
    inline_allowed = ctx.settings.env.lower() == 'test' or os.environ.get('MOBIUS_RECON_INLINE') == '1'
    if not inline_allowed:
        raise HTTPException(status_code=503, detail='in-process RECON is disabled by default; enqueue an isolated worker job (MOBIUS_RECON_INLINE=1 is for local development only)')
    return ReconService(session, ctx.store).run(scan_id)


@router.post("/scans/{scan_id}/recon/jobs", status_code=202, tags=["scans"])
def enqueue_recon_job(scan_id: str, session=SessionDep, who: str = Depends(analyst_id)):
    """Queue APK manifest decoding for the separately deployed isolated worker."""
    scan = _require_scan_owner(session, scan_id, who)
    app = session.get(ApplicationRow, scan.application_id)
    if app is None:
        from ..services.errors import NotFound
        raise NotFound(f"application {scan.application_id} not found")
    job = WorkerQueue(session).enqueue_recon(scan_id, app.artifact_key)
    SqlEventStore(session).emit(
        scan_id, "worker_job_queued",
        {"job_id": job.id, "kind": job.kind, "status": job.status},
        actor="NEXUS",
    )
    return {
        "job_id": job.id,
        "investigation_id": scan_id,
        "kind": job.kind,
        "status": job.status,
        "created_at": job.created_at,
    }


@router.get("/scans/{scan_id}/recon/jobs/{job_id}", tags=["scans"])
def get_recon_job(scan_id: str, job_id: str, session=SessionDep, who: str = Depends(analyst_id)):
    _require_scan_owner(session, scan_id, who)
    job = WorkerQueue(session).get(job_id)
    if job.investigation_id != scan_id or job.kind != "recon_manifest":
        from ..services.errors import NotFound
        raise NotFound(f"worker job {job_id} not found")
    return {
        "job_id": job.id,
        "status": job.status,
        "attempts": job.attempts,
        "worker_id": job.worker_id,
        "error_code": job.error_code,
        "error_detail": job.error_detail,
        "created_at": job.created_at,
        "started_at": job.started_at,
        "finished_at": job.finished_at,
        "applied": job.applied_at is not None,
    }


@router.post("/scans/{scan_id}/recon/jobs/{job_id}/apply", tags=["scans"])
def apply_recon_job(scan_id: str, job_id: str, session=SessionDep, who: str = Depends(analyst_id)):
    _require_scan_owner(session, scan_id, who)
    job = WorkerQueue(session).get(job_id)
    if job.investigation_id != scan_id or job.kind != "recon_manifest":
        from ..services.errors import NotFound
        raise NotFound(f"worker job {job_id} not found")
    if job.status != "succeeded" or not job.result_json:
        from ..services.errors import ScanStateConflict
        raise ScanStateConflict(f"worker job is not ready to apply (status={job.status})")
    if job.applied_at is not None:
        from ..services.errors import ScanStateConflict
        raise ScanStateConflict("worker result has already been applied")
    manifest_xml = job.result_json.get("manifest_xml")
    if not isinstance(manifest_xml, str) or len(manifest_xml.encode("utf-8")) > 10 * 1024 * 1024:
        from ..services.errors import ManifestInvalid
        raise ManifestInvalid("worker returned an invalid or oversized manifest result")
    result = ReconService(session, get_context().store).run(scan_id, manifest_xml=manifest_xml.encode("utf-8"))
    job.applied_at = utcnow()
    SqlEventStore(session).emit(
        scan_id, "worker_job_applied",
        {"job_id": job.id, "kind": job.kind, "status": job.status},
        actor="NEXUS",
    )
    return result


@router.get("/scans/{scan_id}/surface", tags=["scans"])
def get_surface(scan_id: str, session=SessionDep, who: str = Depends(analyst_id)):
    _require_scan_owner(session, scan_id, who)
    ctx = get_context()
    return ReconService(session, ctx.store).surface(scan_id)


@router.post("/scans/{scan_id}/spectre/jobs", status_code=202, tags=["scans"])
def enqueue_spectre_job(scan_id: str, session=SessionDep, who: str = Depends(analyst_id)):
    """Queue DEX indexing in the separately deployed, networkless OCI worker."""
    scan = _require_scan_owner(session, scan_id, who)
    app = session.get(ApplicationRow, scan.application_id)
    if app is None:
        from ..services.errors import NotFound
        raise NotFound(f"application {scan.application_id} not found")
    job = WorkerQueue(session).enqueue_dex_index(scan_id, app.artifact_key)
    SqlEventStore(session).emit(
        scan_id, "worker_job_queued",
        {"job_id": job.id, "kind": job.kind, "status": job.status},
        actor="NEXUS",
    )
    return {
        "job_id": job.id,
        "investigation_id": scan_id,
        "kind": job.kind,
        "status": job.status,
        "created_at": job.created_at,
    }


@router.get("/scans/{scan_id}/spectre/jobs/{job_id}", tags=["scans"])
def get_spectre_job(scan_id: str, job_id: str, session=SessionDep, who: str = Depends(analyst_id)):
    _require_scan_owner(session, scan_id, who)
    job = WorkerQueue(session).get(job_id)
    if job.investigation_id != scan_id or job.kind != "dex_index":
        from ..services.errors import NotFound
        raise NotFound(f"DEX worker job {job_id} not found")
    return {
        "job_id": job.id,
        "kind": job.kind,
        "status": job.status,
        "attempts": job.attempts,
        "worker_id": job.worker_id,
        "error_code": job.error_code,
        "error_detail": job.error_detail,
        "created_at": job.created_at,
        "started_at": job.started_at,
        "finished_at": job.finished_at,
        "applied": job.applied_at is not None,
    }


@router.post("/scans/{scan_id}/spectre/jobs/{job_id}/apply", tags=["scans"])
def apply_spectre_job(scan_id: str, job_id: str, session=SessionDep, who: str = Depends(analyst_id)):
    scan = _require_scan_owner(session, scan_id, who)
    job = WorkerQueue(session).get(job_id)
    if job.investigation_id != scan_id or job.kind != "dex_index":
        from ..services.errors import NotFound
        raise NotFound(f"DEX worker job {job_id} not found")
    if job.status != "succeeded" or not job.result_json:
        from ..services.errors import ScanStateConflict
        raise ScanStateConflict(f"DEX worker job is not ready to apply (status={job.status})")
    if job.applied_at is not None:
        from ..services.errors import ScanStateConflict
        raise ScanStateConflict("DEX worker result has already been applied")
    app = session.get(ApplicationRow, scan.application_id)
    if app is None:
        from ..services.errors import NotFound
        raise NotFound(f"application {scan.application_id} not found")
    try:
        from ..adapters.dex_payload import validate_dex_index_payload
        index = validate_dex_index_payload(
            json.dumps(job.result_json, separators=(",", ":")).encode("utf-8"),
            app.sha256,
        )
    except ValueError as exc:
        from ..services.errors import CodeIndexFailed
        raise CodeIndexFailed(str(exc)) from exc

    result = SpectreService(
        session, get_context().store, indexer=lambda _apk: index
    ).analyse(scan_id)
    job.applied_at = utcnow()
    SqlEventStore(session).emit(
        scan_id, "worker_job_applied",
        {"job_id": job.id, "kind": job.kind, "status": job.status},
        actor="NEXUS",
    )
    return result


@router.post("/scans/{scan_id}/spectre", tags=["scans"])
def run_spectre(scan_id: str, session=SessionDep, who: str = Depends(analyst_id)):
    _require_scan_owner(session, scan_id, who)
    """Run code analysis: build a call graph, search for sink reachability, ask the gate.

    Deterministic - no model is called. Returns one result per candidate component, each
    with the reachability status and the verdict it produced.
    """
    ctx = get_context()
    inline_allowed = ctx.settings.env.lower() == "test" or os.environ.get("MOBIUS_SPECTRE_INLINE") == "1"
    if not inline_allowed:
        raise HTTPException(
            status_code=503,
            detail=(
                "in-process SPECTRE is disabled because DEX parsing handles untrusted APK bytes; "
                "an isolated DEX worker is required (MOBIUS_SPECTRE_INLINE=1 is local-development-only)"
            ),
        )
    return SpectreService(session, ctx.store).analyse(scan_id)


@router.post("/scans/{scan_id}/nexus", tags=["scans"])
def run_nexus(
    scan_id: str,
    max_steps: int | None = Query(default=None, ge=1, le=200),
    session=SessionDep,
    who: str = Depends(analyst_id),
):
    _require_scan_owner(session, scan_id, who)
    """Drive the investigation from the frontier to CLOSED, within a step budget.

    A deterministic dispatcher, not an autonomous planner: it pops the best-scoring entry,
    hands it to the agent that can execute it, and records what it could not do. Closes the
    investigation even when the budget stops it early. No model is called.
    """
    ctx = get_context()
    inline_allowed = ctx.settings.env.lower() == "test" or os.environ.get("MOBIUS_SPECTRE_INLINE") == "1"
    if not inline_allowed:
        raise HTTPException(
            status_code=503,
            detail=(
                "NEXUS is disabled outside test/local development until its SPECTRE DEX-analysis "
                "step runs through the isolated DEX worker (MOBIUS_SPECTRE_INLINE=1 is local-development-only)"
            ),
        )
    return NexusService(session, ctx.store).run(scan_id, max_steps=max_steps)



# ------------------------------------------------------------------------------------
# Safe PoC execution, approvals and cancellation
# ------------------------------------------------------------------------------------


@router.post("/scans/{scan_id}/poc/approvals", status_code=201, tags=["poc"])
def request_poc_approval(
    scan_id: str, payload: PoCApprovalRequest,
    session=SessionDep, who: str = Depends(analyst_id),
):
    _require_scan_owner(session, scan_id, who)
    plan = PoCTestPlan.model_validate(payload.plan)
    if plan.investigation_id != scan_id:
        raise HTTPException(status_code=422, detail="plan investigation_id must match route")
    from ..services.poc_runner import SafePoCRunner
    SafePoCRunner(session)._validate_scope(plan)
    row = PoCApprovalService(session).request(
        plan, requested_by=who, justification=payload.justification,
        risk_summary=payload.risk_summary, expires_at=payload.expires_at,
    )
    return {"id": row.id, "state": row.state, "requested_action": row.requested_action,
            "expires_at": row.expires_at, "investigation_id": row.investigation_id}


@router.post("/scans/{scan_id}/poc/approvals/{approval_id}/resolve", tags=["poc"])
def resolve_poc_approval(
    scan_id: str, approval_id: str, payload: PoCApprovalDecision,
    session=SessionDep, who: str = Depends(analyst_id),
):
    _require_scan_owner(session, scan_id, who)
    try:
        row = PoCApprovalService(session).resolve(
            approval_id, investigation_id=scan_id, decision=payload.decision,
            decided_by=who, note=payload.note,
        )
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return {"id": row.id, "state": row.state, "decided_at": row.decided_at}


@router.post("/scans/{scan_id}/poc/approvals/{approval_id}/cancel", tags=["poc"])
def cancel_poc_approval(
    scan_id: str, approval_id: str,
    session=SessionDep, who: str = Depends(analyst_id),
):
    _require_scan_owner(session, scan_id, who)
    try:
        row = PoCApprovalService(session).cancel(
            approval_id, investigation_id=scan_id, cancelled_by=who,
        )
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return {"id": row.id, "state": row.state}


@router.post("/scans/{scan_id}/poc/execute", tags=["poc"])
def execute_poc(
    scan_id: str, payload: PoCTestPlan,
    session=SessionDep, who: str = Depends(analyst_id),
):
    _require_scan_owner(session, scan_id, who)
    if payload.investigation_id != scan_id:
        raise HTTPException(status_code=422, detail="plan investigation_id must match route")
    ctx = get_context()
    result = PoCExecutionService(session, ctx.store).execute_and_persist(payload)
    return {"run_id": result.run_id, "plan_id": result.plan_id, "status": result.status,
            "evidence_ids": list(result.evidence_ids), "input_sha256": result.input_sha256,
            "output_sha256": result.output_sha256, "output": result.result.output_json}


@router.post("/scans/{scan_id}/poc/plans/{plan_id}/cancel", tags=["poc"])
def cancel_poc_execution(
    scan_id: str, plan_id: str, session=SessionDep, who: str = Depends(analyst_id),
):
    _require_scan_owner(session, scan_id, who)
    if not request_poc_cancel(plan_id):
        raise HTTPException(status_code=409, detail="no active PoC execution for this plan in this process")
    SqlEventStore(session).emit(
        scan_id, "poc_cancel_requested", {"plan_id": plan_id}, actor=who,
    )
    return {"plan_id": plan_id, "cancel_requested": True, "mode": "cooperative-between-steps"}


@router.get("/scans/{scan_id}/poc/runs", tags=["poc"])
def list_poc_runs(scan_id: str, session=SessionDep, who: str = Depends(analyst_id)):
    _require_scan_owner(session, scan_id, who)
    rows = session.query(PoCRunRow).filter(
        PoCRunRow.investigation_id == scan_id
    ).order_by(PoCRunRow.created_at.desc()).limit(100).all()
    return {"items": [{
        "id": row.id, "plan_id": row.plan_id, "approval_id": row.approval_id,
        "status": row.status, "exit_status": row.exit_status,
        "target_sha256": row.target_sha256, "input_sha256": row.input_sha256,
        "output_sha256": row.output_sha256, "tool_versions": row.tool_versions,
        "started_at": row.started_at, "finished_at": row.finished_at,
        "duration_ms": row.duration_ms, "cleanup": row.cleanup_json,
    } for row in rows]}


# ------------------------------------------------------------------------------------
# ARCHIVIST - the report
# ------------------------------------------------------------------------------------


@router.post("/scans/{scan_id}/report", tags=["scans"])
def write_report(scan_id: str, session=SessionDep, who: str = Depends(analyst_id)):
    _require_scan_owner(session, scan_id, who)
    """Write the investigation report and store it as evidence.

    Returns the Markdown itself as well as the evidence id, so a caller does not have to make
    a second request to read what was just written. No model is called: the document is
    composed from stored rows.
    """
    ctx = get_context()
    return ArchivistService(session, ctx.store).write(scan_id)


@router.get("/scans/{scan_id}/report", tags=["scans"], response_class=PlainTextResponse)
def get_report(scan_id: str, session=SessionDep, who: str = Depends(analyst_id)):
    _require_scan_owner(session, scan_id, who)
    """The most recently written report, as Markdown.

    Reads the stored artefact rather than rebuilding it, so what a reader downloads is what
    the scan produced, even if observations were added afterwards.
    """
    ctx = get_context()
    return PlainTextResponse(
        ArchivistService(session, ctx.store).latest(scan_id),
        media_type="text/markdown; charset=utf-8",
    )


# ------------------------------------------------------------------------------------
# Event stream (SSE)
# ------------------------------------------------------------------------------------


def _sse(event) -> str:
    return (
        f"id: {event.seq}\n"
        f"event: {event.type}\n"
        f"data: {json.dumps(event.payload, separators=(',', ':'))}\n\n"
    )


@router.get("/scans/{scan_id}/stream", tags=["stream"])
async def stream_events(
    scan_id: str,
    request: Request,
    after: int = Query(default=0, ge=0),
    follow: bool = Query(default=True),
    idle_timeout: float = Query(default=30.0, ge=0.0, le=300.0),
    last_event_id: str | None = Header(default=None),
    who: str = Depends(analyst_id),
):
    """Server-sent events, replayed from a cursor.

    Deliberately implemented by polling the event table rather than by Postgres
    LISTEN/NOTIFY. That keeps replay, ordering and the `Last-Event-ID` contract identical on
    SQLite and Postgres, and means the resume path is exercised continuously instead of only
    after a disconnect. The cost is a small poll interval; the `EventEmitter` port exists so
    a push transport can replace this without touching any caller.
    """
    ctx = get_context()
    start = after
    if last_event_id:
        try:
            start = max(start, int(last_event_id))
        except ValueError:
            pass

    with ctx.session() as probe:
        _require_scan_owner(probe, scan_id, who)

    async def generator():
        last = start
        idle = 0.0
        while True:
            if await request.is_disconnected():
                return
            with ctx.session() as session:
                events = SqlEventStore(session).read_after(scan_id, after_seq=last, limit=200)
                row = session.get(InvestigationRow, scan_id)
                terminal = row is not None and fsm.is_terminal(InvestigationState(row.state))
            if events:
                for event in events:
                    last = event.seq
                    yield _sse(event)
                idle = 0.0
                continue
            if terminal:
                # Everything that will ever be written has been written. Closing here is
                # what lets a client stop reconnecting without guessing.
                yield "event: stream_end\ndata: {}\n\n"
                return
            if not follow or idle >= idle_timeout:
                return
            await asyncio.sleep(0.2)
            idle += 0.2
            if idle % 5 < 0.2:
                yield ": keep-alive\n\n"

    return StreamingResponse(
        generator(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


# ------------------------------------------------------------------------------------
# Serialisation helpers
# ------------------------------------------------------------------------------------


def _app_body(app) -> dict[str, object]:
    return {
        "id": app.id,
        "sha256": app.sha256,
        "package_name": app.package_name,
        "version_name": app.version_name,
        "file_size": app.file_size,
        "artifact_key": app.artifact_key,
    }


def _scan_body(session, scan_id: str) -> dict[str, object]:
    from ..services.errors import NotFound

    row = session.get(InvestigationRow, scan_id)
    if row is None:
        raise NotFound(f"investigation {scan_id} not found")
    store = SqlEventStore(session)
    app = session.get(ApplicationRow, row.application_id)
    authorization = session.get(AuthorizationRow, row.authorization_id) if row.authorization_id else None
    return {
        "id": row.id,
        "state": row.state,
        "application": ({"id": app.id, "sha256": app.sha256, "package_name": app.package_name, "version_name": app.version_name, "file_size": app.file_size} if app else None),
        "authorization": ({"id": authorization.id, "target_package": authorization.target_package, "max_intensity": authorization.max_intensity, "expires_at": authorization.expires_at, "revoked": authorization.revoked_at is not None} if authorization else None),
        "paused": row.paused_at is not None,
        "application_id": row.application_id,
        "authorization_id": row.authorization_id,
        "intensity": row.intensity,
        "objective": row.objective,
        "budget": row.budget_json,
        "used": row.used_json,
        "stop_reason": row.stop_reason,
        "last_event_seq": store.current_seq(scan_id),
    }
