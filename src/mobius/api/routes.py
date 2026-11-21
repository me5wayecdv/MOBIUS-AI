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
from ..services.provider_analysis import ProviderAnalysisService
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
            detail="model consent must be granted explicitly after scan creation via PUT /scans/{scan_id}/model-consent naming an approved provider",
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
    if payload.enabled and payload.provider not in {"ollama", "opencode"}:
        from ..services.errors import ScanStateConflict
        raise ScanStateConflict(
            "enabled model consent must explicitly name an approved provider "
            "(ollama=local, opencode=prompts leave the machine to upstream providers)"
        )
    if not payload.enabled and payload.provider is not None:
        from ..services.errors import ScanStateConflict
        raise ScanStateConflict("disabled model consent must not name a provider")
    if payload.auto_veritas and not payload.enabled:
        from ..services.errors import ScanStateConflict
        raise ScanStateConflict("auto VERITAS review requires enabled model consent")
    scan.llm_data_sharing = {
        "enabled": payload.enabled,
        "provider": payload.provider if payload.enabled else None,
        "auto_veritas": bool(payload.auto_veritas and payload.enabled),
    }
    SqlEventStore(session).emit(
        scan_id,
        "model_consent_updated",
        {
            "enabled": payload.enabled,
            "provider": payload.provider if payload.enabled else None,
            "auto_veritas": bool(payload.auto_veritas and payload.enabled),
        },
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
    from ..services.errors import (
        BudgetExhausted,
        ModelConsentRequiredError,
        ModelOutputInvalidError,
        ModelProviderUnavailable,
    )
    from ..services.model_provider import (
        ModelBudgetExceeded,
        ModelConsentRequired,
        ModelOutputInvalid,
        ModelProviderError,
    )
    from ..services.nexus_hypotheses import NexusHypothesisService

    ctx = get_context()
    try:
        return NexusHypothesisService(
            session,
            gateway=ctx.model_gateway,
            session_factory=ctx.session_factory,
            store=ctx.store,
            max_output_tokens=ctx.settings.model_max_output_tokens,
            max_repair_attempts=ctx.settings.model_max_repair_attempts,
        ).generate(scan_id, component=component)
    except ModelConsentRequired as exc:
        raise ModelConsentRequiredError(str(exc)) from exc
    except (ModelOutputInvalid, ValueError) as exc:
        # Stable client-facing message: raw validation/parse details can carry
        # model output content and never leave the server (same rule as VERITAS).
        raise ModelOutputInvalidError(
            "model output failed validation; rejection recorded, no hypotheses persisted"
        ) from exc
    except ModelBudgetExceeded as exc:
        raise BudgetExhausted(str(exc)) from exc
    except ModelProviderError as exc:
        # Provider unreachable/timeout/transport failure: explicit 503, never a
        # bare 500; raw transport details never leave the server.
        raise ModelProviderUnavailable(
            "model provider unavailable; retry later"
        ) from exc


@router.get("/scans/{scan_id}/decisions", tags=["scans"])
def get_decisions(
    scan_id: str,
    after: str | None = Query(default=None, max_length=40),
    limit: int = Query(default=100, ge=1, le=200),
    session=SessionDep,
    who: str = Depends(analyst_id),
):
    """Replay the investigation's persisted decision provenance (D-025).

    Decision rows, including rejected alternatives and full model provenance,
    in deterministic (created_at, id) order. Pagination is keyset-based and
    bounded: at most `limit` rows per call (default 100, max 200), ordered and
    filtered in SQL - the route never loads the scan's full history. `after`
    must name a DecisionRow id inside this investigation (unknown or
    cross-investigation cursors are 404); follow `next_cursor` while it is
    non-null for a complete, non-overlapping replay.
    """
    from sqlalchemy import and_

    _require_scan_owner(session, scan_id, who)
    query = session.query(DecisionRow).filter(
        DecisionRow.investigation_id == scan_id
    )
    if after is not None:
        cursor = session.get(DecisionRow, after)
        if cursor is None or cursor.investigation_id != scan_id:
            from ..services.errors import NotFound

            raise NotFound(f"decision cursor {after} not found in this investigation")
        query = query.filter(
            (DecisionRow.created_at > cursor.created_at)
            | (
                and_(
                    DecisionRow.created_at == cursor.created_at,
                    DecisionRow.id > cursor.id,
                )
            )
        )
    rows = query.order_by(
        DecisionRow.created_at.asc(), DecisionRow.id.asc()
    ).limit(limit + 1).all()
    has_more = len(rows) > limit
    rows = rows[:limit]
    next_cursor = rows[-1].id if rows and has_more else None
    return {"next_cursor": next_cursor, "items": [{
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
    from ..services.errors import (
        BudgetExhausted,
        ModelConsentRequiredError,
        ModelOutputInvalidError,
        ModelProviderUnavailable,
        NotFound,
    )
    from ..services.model_provider import (
        ModelBudgetExceeded,
        ModelConsentRequired,
        ModelOutputInvalid,
        ModelProviderError,
    )
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
            store=ctx.store,
            max_output_tokens=ctx.settings.model_max_output_tokens,
        ).review(finding_id, producer_model_id=producer_model_id)
    except ModelConsentRequired as exc:
        raise ModelConsentRequiredError(str(exc)) from exc
    except (ModelOutputInvalid, ValueError) as exc:
        # Stable client-facing message: raw validation/parse details can carry
        # model output content and never leave the server.
        raise ModelOutputInvalidError(
            "reviewer model output failed validation or review input was not usable"
        ) from exc
    except ModelBudgetExceeded as exc:
        raise BudgetExhausted(str(exc)) from exc
    except ModelProviderError as exc:
        # Provider unreachable/timeout/transport failure (ModelUnavailable and any
        # other gateway-level failure): explicit 503, never a bare 500. The client
        # gets a stable message; raw transport details never leave the server.
        raise ModelProviderUnavailable(
            "reviewer model provider unavailable; retry later"
        ) from exc


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


@router.post("/scans/{scan_id}/provider-analysis", tags=["scans"])
def provider_analysis(scan_id: str, session=SessionDep, who: str = Depends(analyst_id)):
    """Run the static provider detector on this scan's APK and validate the results.

    Deterministic: the detector emits attributes and an evidence document per
    exported provider operation, the exported-component-no-permission gate
    decides every finding. Unknown evidence stays missing, never guessed.
    """
    _require_scan_owner(session, scan_id, who)
    ctx = get_context()
    # The opt-in flag is a local-development escape hatch only: it is ignored
    # in production, where untrusted APK bytes never run through this process.
    inline_allowed = ctx.settings.env.lower() == "test" or (
        os.environ.get("MOBIUS_PROVIDER_INLINE") == "1" and not ctx.settings.is_production
    )
    if not inline_allowed:
        raise HTTPException(
            status_code=503,
            detail=(
                "in-process provider analysis is disabled because it parses untrusted APK bytes; "
                "enqueue an isolated worker job (MOBIUS_PROVIDER_INLINE=1 is local-development-only)"
            ),
        )
    return ProviderAnalysisService(session, ctx.store).run(scan_id, validated_by=who)


@router.post("/scans/{scan_id}/provider-analysis/jobs", status_code=202, tags=["scans"])
def enqueue_provider_analysis_job(scan_id: str, session=SessionDep, who: str = Depends(analyst_id)):
    """Queue provider-exposure analysis in the separately deployed, networkless OCI worker."""
    scan = _require_scan_owner(session, scan_id, who)
    app = session.get(ApplicationRow, scan.application_id)
    if app is None:
        from ..services.errors import NotFound
        raise NotFound(f"application {scan.application_id} not found")
    job = WorkerQueue(session).enqueue_provider_analysis(scan_id, app.artifact_key)
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


@router.post("/scans/{scan_id}/secrets-analysis/jobs", status_code=202, tags=["scans"])
def enqueue_secrets_analysis_job(scan_id: str, session=SessionDep, who: str = Depends(analyst_id)):
    """Queue isolated secrets candidate analysis in the networkless OCI worker.

    Disabled by default (MOBIUS_SECRETS_ENQUEUE_ENABLED != "1" -> 503 before
    any job row is created). While no digest-pinned worker image is
    published, an ENABLED route still does not yield analysis: claim() is
    kind-blind, so a running worker without MOBIUS_SECRETS_IMAGE claims the
    job and _tool_for raises, failing it terminally with a bounded config
    error (no execution, no crash, re-enqueue possible). No in-process
    escape hatch exists for this analysis: untrusted APK bytes never parse
    in the API process."""
    ctx = get_context()
    if not ctx.settings.secrets_enqueue_enabled:
        raise HTTPException(
            status_code=503,
            detail=(
                "secrets-analysis enqueue is disabled: no digest-pinned worker image "
                "is published, and a queued job would be claimed and terminally "
                "failed by an unconfigured worker"
            ),
        )
    scan = _require_scan_owner(session, scan_id, who)
    app = session.get(ApplicationRow, scan.application_id)
    if app is None:
        from ..services.errors import NotFound
        raise NotFound(f"application {scan.application_id} not found")
    job = WorkerQueue(session).enqueue_secrets_analysis(scan_id, app.artifact_key)
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


@router.get("/scans/{scan_id}/provider-analysis/jobs/{job_id}", tags=["scans"])
def get_provider_analysis_job(scan_id: str, job_id: str, session=SessionDep, who: str = Depends(analyst_id)):
    _require_scan_owner(session, scan_id, who)
    job = WorkerQueue(session).get(job_id)
    if job.investigation_id != scan_id or job.kind != "provider_analysis":
        from ..services.errors import NotFound
        raise NotFound(f"provider-analysis worker job {job_id} not found")
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


def _reject_unappliable_provider_job(scan_id: str, job, reason: str):
    """An unappliable payload must not deadlock the investigation. The
    rejection is committed in its OWN session because the rejecting request's
    transaction rolls back with the HTTP error; the reason stays on the job
    row (error_code/error_detail) as retained evidence."""
    ctx = get_context()
    mark = ctx.session()
    try:
        WorkerQueue(mark).terminal_reject(job.id, "InvalidWorkerPayload", reason)
        SqlEventStore(mark).emit(
            scan_id, "worker_job_rejected",
            {"job_id": job.id, "kind": job.kind, "reason": "unappliable result"},
            actor="NEXUS",
        )
        mark.commit()
    finally:
        mark.close()
    from ..services.errors import CodeIndexFailed
    raise CodeIndexFailed(reason)


@router.post("/scans/{scan_id}/provider-analysis/jobs/{job_id}/apply", tags=["scans"])
def apply_provider_analysis_job(scan_id: str, job_id: str, session=SessionDep, who: str = Depends(analyst_id)):
    scan = _require_scan_owner(session, scan_id, who)
    job = WorkerQueue(session).get(job_id)
    if job.investigation_id != scan_id or job.kind != "provider_analysis":
        from ..services.errors import NotFound
        raise NotFound(f"provider-analysis worker job {job_id} not found")
    if job.status != "succeeded" or not job.result_json:
        from ..services.errors import ScanStateConflict
        raise ScanStateConflict(f"provider-analysis worker job is not ready to apply (status={job.status})")
    if job.applied_at is not None:
        from ..services.errors import ScanStateConflict
        raise ScanStateConflict("provider-analysis worker result has already been applied")
    app = session.get(ApplicationRow, scan.application_id)
    if app is None:
        from ..services.errors import NotFound
        raise NotFound(f"application {scan.application_id} not found")
    try:
        from ..adapters.provider_payload import validate_provider_analysis_payload
        result = validate_provider_analysis_payload(
            json.dumps(job.result_json, separators=(",", ":")).encode("utf-8"),
            app.sha256,
        )
    except ValueError as exc:
        _reject_unappliable_provider_job(scan_id, job, str(exc))

    # Anchor comparison before apply. Anchors: the intake digest (app.sha256),
    # a FRESH rehash of the stored artifact bytes by this API process, the
    # host-side staged digest the runner stored (computed outside the
    # container), and the worker payload's own digest (already checked against
    # app.sha256 by the validator). The worker's self-report is never the only
    # proof of which bytes were analyzed.
    from hashlib import sha256 as _sha256
    rehashed = _sha256(get_context().store.get(app.artifact_key)).hexdigest()
    if rehashed != app.sha256:
        _reject_unappliable_provider_job(
            scan_id, job, "stored artifact bytes no longer match the intake digest")
    if not job.staged_sha256 or job.staged_sha256 != app.sha256:
        _reject_unappliable_provider_job(
            scan_id, job,
            "worker staged-input digest is missing or does not match the "
            "authorized artifact digest")
    # Package consistency against the stored recon result when one exists:
    # the surface_ready event recorded the package the recon pipeline parsed
    # from the same artifact. (Consistency check, not an independent parse.)
    from ..adapters.models import EventRow as _EventRow
    from sqlalchemy import select as _select
    recon_event = session.execute(
        _select(_EventRow)
        .where(_EventRow.investigation_id == scan_id,
               _EventRow.type == "surface_ready")
        .order_by(_EventRow.seq.desc())
        .limit(1)
    ).scalar_one_or_none()
    recon_package = (recon_event.payload or {}).get("package") if recon_event else None
    if recon_package and recon_package != result.package_name:
        _reject_unappliable_provider_job(
            scan_id, job,
            "worker-reported package contradicts the stored recon manifest package")

    # Authorization revalidated at apply time, BEFORE the claim: a revoked,
    # expired, rebinding or wrong-package authorization makes this payload
    # unappliable, so the job is terminally rejected (committed separately)
    # instead of failing after the claim and rolling back into a dead end.
    from ..services.intake import is_expired as _is_expired
    authorization = (
        session.get(AuthorizationRow, scan.authorization_id)
        if scan.authorization_id else None
    )
    if authorization is None:
        _reject_unappliable_provider_job(
            scan_id, job, "investigation has no active APK authorization at apply time")
    if authorization.revoked_at is not None or _is_expired(authorization.expires_at):
        _reject_unappliable_provider_job(
            scan_id, job, "APK authorization is revoked or expired at apply time")
    if authorization.apk_sha256 != app.sha256:
        _reject_unappliable_provider_job(
            scan_id, job, "APK authorization is bound to a different artifact")
    if authorization.target_package != result.package_name:
        _reject_unappliable_provider_job(
            scan_id, job,
            "authorized target package does not match the package in the worker result")

    # Legacy or raced second job: if another provider job was already applied
    # for this investigation, this one terminalizes truthfully (rejected, not
    # blocking) instead of looping on a conflict after the claim.
    from ..adapters.models import WorkerJobRow as _WJR
    other_applied = session.execute(
        _select(_WJR)
        .where(_WJR.investigation_id == scan_id,
               _WJR.kind == "provider_analysis",
               _WJR.applied_at.is_not(None),
               _WJR.id != job.id)
        .limit(1)
    ).scalar_one_or_none()
    if other_applied is not None:
        _reject_unappliable_provider_job(
            scan_id, job,
            f"provider analysis was already applied by worker job {other_applied.id}")

    # Atomic apply claim: exactly one concurrent applier wins; the loser gets
    # 409. A failure later in this request rolls the claim back with it.
    WorkerQueue(session).claim_apply(job_id)

    outcome = ProviderAnalysisService(session, get_context().store).run_from_payload(
        scan_id, result, validated_by=who, applied_job_id=job.id
    )
    SqlEventStore(session).emit(
        scan_id, "worker_job_applied",
        {"job_id": job.id, "kind": job.kind, "status": job.status},
        actor="NEXUS",
    )
    return outcome


@router.get("/scans/{scan_id}/secrets-analysis/jobs/{job_id}", tags=["scans"])
def get_secrets_analysis_job(scan_id: str, job_id: str, session=SessionDep, who: str = Depends(analyst_id)):
    _require_scan_owner(session, scan_id, who)
    job = WorkerQueue(session).get(job_id)
    if job.investigation_id != scan_id or job.kind != "secrets_analysis":
        from ..services.errors import NotFound
        raise NotFound(f"secrets-analysis worker job {job_id} not found")
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


def _reject_unappliable_secrets_job(scan_id: str, job, reason: str):
    """Same contract as the provider twin: an unappliable payload must not
    deadlock the investigation. The rejection is committed in its OWN session
    because the rejecting request's transaction rolls back with the HTTP
    error; the reason stays on the job row as retained evidence."""
    ctx = get_context()
    mark = ctx.session()
    try:
        WorkerQueue(mark).terminal_reject(job.id, "InvalidWorkerPayload", reason)
        SqlEventStore(mark).emit(
            scan_id, "worker_job_rejected",
            {"job_id": job.id, "kind": job.kind, "reason": "unappliable result"},
            actor="NEXUS",
        )
        mark.commit()
    finally:
        mark.close()
    from ..services.errors import CodeIndexFailed
    raise CodeIndexFailed(reason)


@router.post("/scans/{scan_id}/secrets-analysis/jobs/{job_id}/apply", tags=["scans"])
def apply_secrets_analysis_job(scan_id: str, job_id: str, session=SessionDep, who: str = Depends(analyst_id)):
    """Apply a validated isolated secrets-analysis worker payload.

    Same anchor, authorization and lifecycle gates as the provider apply
    route, plus a bounded zip-metadata cross-check of the worker's DEX
    ledger: entry names and sizes only, never a parse. Queueing exists
    (POST .../secrets-analysis/jobs) but a queued job only executes where
    a worker runs with a digest-pinned MOBIUS_SECRETS_IMAGE; the image is
    not yet published through the reviewed deployment path.
    """
    scan = _require_scan_owner(session, scan_id, who)
    job = WorkerQueue(session).get(job_id)
    if job.investigation_id != scan_id or job.kind != "secrets_analysis":
        from ..services.errors import NotFound
        raise NotFound(f"secrets-analysis worker job {job_id} not found")
    if job.status != "succeeded" or not job.result_json:
        from ..services.errors import ScanStateConflict
        raise ScanStateConflict(f"secrets-analysis worker job is not ready to apply (status={job.status})")
    if job.applied_at is not None:
        from ..services.errors import ScanStateConflict
        raise ScanStateConflict("secrets-analysis worker result has already been applied")
    app = session.get(ApplicationRow, scan.application_id)
    if app is None:
        from ..services.errors import NotFound
        raise NotFound(f"application {scan.application_id} not found")
    try:
        from ..adapters.secrets_payload import validate_secrets_analysis_payload
        result = validate_secrets_analysis_payload(
            json.dumps(job.result_json, separators=(",", ":")).encode("utf-8"),
            app.sha256,
        )
    except ValueError as exc:
        _reject_unappliable_secrets_job(scan_id, job, str(exc))

    # Anchor comparison before apply, identical to the provider route: the
    # intake digest, a FRESH rehash of the stored artifact bytes by this API
    # process, and the host-side staged digest the runner stored. The
    # worker's self-report is never the only proof of which bytes were
    # analysed.
    from hashlib import sha256 as _sha256
    artifact_bytes = get_context().store.get(app.artifact_key)
    if _sha256(artifact_bytes).hexdigest() != app.sha256:
        _reject_unappliable_secrets_job(
            scan_id, job, "stored artifact bytes no longer match the intake digest")
    if not job.staged_sha256 or job.staged_sha256 != app.sha256:
        _reject_unappliable_secrets_job(
            scan_id, job,
            "worker staged-input digest is missing or does not match the "
            "authorized artifact digest")

    # Bounded zip-metadata cross-check of the worker-asserted DEX ledger:
    # the multiset of classes*.dex entry (name, size) pairs in the stored
    # artifact must equal the ledger's. Names and sizes only - the API never
    # parses APK or DEX content.
    import io as _io
    import re as _re
    import zipfile as _zipfile
    from collections import Counter as _Counter
    try:
        with _zipfile.ZipFile(_io.BytesIO(artifact_bytes)) as archive:
            actual = _Counter(
                (info.filename, info.file_size)
                for info in archive.infolist()
                if _re.fullmatch(r"classes\d*\.dex", info.filename)
            )
    except _zipfile.BadZipFile:
        # Fail closed with a bounded reason, not an unhandled 500: the ledger
        # cross-check could not run, so the payload is unappliable.
        _reject_unappliable_secrets_job(
            scan_id, job,
            "stored artifact is not a readable zip archive; "
            "the DEX ledger cross-check could not run")
    reported = _Counter((b.entry, b.size_bytes) for b in result.ledger)
    if actual != reported:
        _reject_unappliable_secrets_job(
            scan_id, job,
            "worker-reported DEX ledger contradicts the stored artifact's zip metadata")

    from ..adapters.models import EventRow as _EventRow
    from sqlalchemy import select as _select
    recon_event = session.execute(
        _select(_EventRow)
        .where(_EventRow.investigation_id == scan_id,
               _EventRow.type == "surface_ready")
        .order_by(_EventRow.seq.desc())
        .limit(1)
    ).scalar_one_or_none()
    recon_package = (recon_event.payload or {}).get("package") if recon_event else None
    if recon_package and recon_package != result.package_name:
        _reject_unappliable_secrets_job(
            scan_id, job,
            "worker-reported package contradicts the stored recon manifest package")

    # Authorization revalidated at apply time, BEFORE the claim (same
    # contract as the provider route).
    from ..services.intake import is_expired as _is_expired
    authorization = (
        session.get(AuthorizationRow, scan.authorization_id)
        if scan.authorization_id else None
    )
    if authorization is None:
        _reject_unappliable_secrets_job(
            scan_id, job, "investigation has no active APK authorization at apply time")
    if authorization.revoked_at is not None or _is_expired(authorization.expires_at):
        _reject_unappliable_secrets_job(
            scan_id, job, "APK authorization is revoked or expired at apply time")
    if authorization.apk_sha256 != app.sha256:
        _reject_unappliable_secrets_job(
            scan_id, job, "APK authorization is bound to a different artifact")
    if authorization.target_package != result.package_name:
        _reject_unappliable_secrets_job(
            scan_id, job,
            "authorized target package does not match the package in the worker result")

    # Legacy or raced second job, same as the provider route.
    from ..adapters.models import WorkerJobRow as _WJR
    other_applied = session.execute(
        _select(_WJR)
        .where(_WJR.investigation_id == scan_id,
               _WJR.kind == "secrets_analysis",
               _WJR.applied_at.is_not(None),
               _WJR.id != job.id)
        .limit(1)
    ).scalar_one_or_none()
    if other_applied is not None:
        _reject_unappliable_secrets_job(
            scan_id, job,
            f"secrets analysis was already applied by worker job {other_applied.id}")

    # Atomic apply claim: exactly one concurrent applier wins; the loser gets
    # 409. A failure later in this request rolls the claim back with it.
    WorkerQueue(session).claim_apply(job_id)

    from ..services.secrets_analysis import SecretsAnalysisService
    outcome = SecretsAnalysisService(session, get_context().store).run_from_payload(
        scan_id, result, validated_by=who, applied_job_id=job.id
    )
    SqlEventStore(session).emit(
        scan_id, "worker_job_applied",
        {"job_id": job.id, "kind": job.kind, "status": job.status},
        actor="NEXUS",
    )
    return outcome


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
    result = NexusService(session, ctx.store).run(scan_id, max_steps=max_steps)
    # Commit the pipeline transaction BEFORE the optional advisory review pass.
    # The pipeline session holds the investigation row write lock (event_seq
    # allocator) until commit; the review pass reserves/settles token budget on
    # independent sessions that need the same row, so running it earlier would
    # self-block under PostgreSQL. The teardown commit below stays a no-op.
    session.commit()
    try:
        auto_review = _maybe_veritas_auto_review(ctx, scan_id)
    except Exception:
        # The optional pass must never mask the deterministic scan result: a
        # review-pass failure after the core commit is reported with a fixed
        # token, never surfaced as a whole-scan failure.
        auto_review = {
            "attempted": 0,
            "completed": 0,
            "failed": 0,
            "skipped": 0,
            "failures": [],
            "skips": [],
            "advisory_only": True,
            "status": "review-pass-error",
        }
    if auto_review is not None:
        result = {**result, "veritas_auto_review": auto_review}
    return result


def _maybe_veritas_auto_review(ctx, scan_id: str):
    """Run the opt-in post-commit VERITAS auto-review pass, or return None.

    Reads the consent flag on a short fresh session (the pipeline session is
    already committed and closed to new work). Returns None when the
    investigation did not opt in, so the response shape is unchanged for
    existing clients.
    """
    probe = ctx.session()
    try:
        scan = probe.get(InvestigationRow, scan_id)
        consent = dict(scan.llm_data_sharing or {}) if scan is not None else {}
    finally:
        probe.close()
    if consent.get("enabled") is not True or consent.get("auto_veritas") is not True:
        return None
    from ..services.veritas_auto import run_auto_review_pass

    return run_auto_review_pass(
        session_factory=ctx.session_factory,
        gateway=ctx.model_gateway,
        investigation_id=scan_id,
        store=ctx.store,
        max_reviews=ctx.settings.veritas_auto_max_reviews,
    )



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
    result = PoCExecutionService(session, ctx.store, native_adapter=ctx.native_fixture_adapter,
        owned_android_adapter=ctx.owned_android_fixture_adapter).execute_and_persist(payload)
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
        "hypothesis_ids": list(row.hypothesis_ids or []),
    } for row in rows]}


@router.get("/scans/{scan_id}/poc/runs/{run_id}/evidence", tags=["poc"])
def readback_poc_run(scan_id: str, run_id: str, session=SessionDep, who: str = Depends(analyst_id)):
    _require_scan_owner(session, scan_id, who)
    ctx=get_context()
    service=PoCExecutionService(session,ctx.store)
    try:row=service.get(run_id)
    except LookupError as exc:raise HTTPException(status_code=404,detail="PoC run not found") from exc
    if row.investigation_id!=scan_id:raise HTTPException(status_code=404,detail="PoC run not found")
    return service.readback(run_id,investigation_id=scan_id)


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
