"""HTTP routes. Every handler is a thin translation between HTTP and a service."""

from __future__ import annotations

import asyncio
import json

from fastapi import APIRouter, Depends, Header, Query, Request, UploadFile
from fastapi.responses import JSONResponse, StreamingResponse

from ..adapters.events import SqlEventStore
from ..adapters.models import EvidenceRow, FindingRow, InvestigationRow
from ..core import fsm, gates
from ..core.enums import EvidenceKind, InvestigationState, RejectionReason
from ..services.evidence import EvidenceService
from ..services.intake import IntakeService
from ..services.recon import ReconService
from ..services.validation import ValidationService
from .deps import analyst_id, get_context
from .schemas import (
    AuthorizationCreate,
    PauseRequest,
    ScanCreate,
    ValidationRequest,
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
    session=Depends(_session),
    who: str = Depends(analyst_id),
):
    ctx = get_context()
    data = await file.read()
    service = IntakeService(session, ctx.store)
    app, created = service.create_application(data, file.filename or "", uploaded_by=who)
    body = _app_body(app)
    if not created and not force:
        body["duplicate"] = True
    return JSONResponse(status_code=201, content=body)


@router.post("/authorizations", status_code=201, tags=["authorizations"])
def create_authorization(
    payload: AuthorizationCreate,
    session=Depends(_session),
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
    session=Depends(_session),
    who: str = Depends(analyst_id),
):
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


@router.get("/scans/{scan_id}", tags=["scans"])
def get_scan(scan_id: str, session=Depends(_session)):
    return _scan_body(session, scan_id)


@router.post("/scans/{scan_id}/pause", tags=["scans"])
def pause_scan(
    scan_id: str, payload: PauseRequest | None = None, session=Depends(_session), who: str = Depends(analyst_id)
):
    ctx = get_context()
    IntakeService(session, ctx.store).pause(scan_id, by=who, reason=(payload.reason if payload else None))
    return _scan_body(session, scan_id)


@router.post("/scans/{scan_id}/resume", tags=["scans"])
def resume_scan(scan_id: str, session=Depends(_session), who: str = Depends(analyst_id)):
    ctx = get_context()
    IntakeService(session, ctx.store).resume(scan_id, by=who)
    return _scan_body(session, scan_id)


@router.post("/scans/{scan_id}/cancel", tags=["scans"])
def cancel_scan(scan_id: str, session=Depends(_session), who: str = Depends(analyst_id)):
    ctx = get_context()
    IntakeService(session, ctx.store).cancel(scan_id, by=who)
    return _scan_body(session, scan_id)


@router.get("/scans/{scan_id}/events", tags=["scans"])
def get_events(
    scan_id: str,
    after: int = Query(default=0, ge=0),
    limit: int = Query(default=200, ge=1, le=1000),
    session=Depends(_session),
):
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
def get_findings(scan_id: str, session=Depends(_session)):
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


@router.get("/scans/{scan_id}/evidence", tags=["scans"])
def get_evidence(scan_id: str, session=Depends(_session)):
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


@router.post("/scans/{scan_id}/evidence", status_code=201, tags=["scans"])
def post_evidence(
    scan_id: str,
    kind: EvidenceKind,
    summary: str,
    content: str,
    session=Depends(_session),
    who: str = Depends(analyst_id),
):
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
    session=Depends(_session),
    who: str = Depends(analyst_id),
):
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
def run_recon(scan_id: str, session=Depends(_session)):
    """Run the deterministic manifest analysis. Idempotent only in the sense that it
    refuses to run twice: re-running would duplicate observations and frontier entries."""
    ctx = get_context()
    return ReconService(session, ctx.store).run(scan_id)


@router.get("/scans/{scan_id}/surface", tags=["scans"])
def get_surface(scan_id: str, session=Depends(_session)):
    ctx = get_context()
    return ReconService(session, ctx.store).surface(scan_id)


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
        if probe.get(InvestigationRow, scan_id) is None:
            from ..services.errors import NotFound

            raise NotFound(f"investigation {scan_id} not found")

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
    return {
        "id": row.id,
        "state": row.state,
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
