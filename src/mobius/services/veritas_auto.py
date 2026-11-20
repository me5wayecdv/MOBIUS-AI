"""Optional post-pipeline VERITAS auto-review pass (D-026).

This module wires the advisory VERITAS review into the investigation path as an
OPT-IN, POST-COMMIT pass. It exists because the request session that runs the
SPECTRE/NEXUS pipeline holds the investigation row write lock (the event_seq
allocator) until teardown commit; calling a review inline would make the
review's independent budget sessions wait on a lock their own caller holds -
a self-deadlock under PostgreSQL. The route therefore commits the pipeline
transaction first, then runs this pass on fresh per-finding sessions.

Guarantees:
- Advisory only: reviews never create, edit, confirm, or reject findings; the
  deterministic ValidationService gates stay the sole verdict authority.
- Fail-closed provenance: only findings from a known deterministic producer
  WITH persisted evidence references are eligible, sent with the explicit
  "deterministic-pipeline" sentinel; anything else is skipped with a fixed
  token and no independence claim is possible (VeritasReviewService itself
  fails closed on a persisted producer-decision conflict and always reports
  producer_model_verified/independence_assured=false for sentinel reviews).
- Concurrency-safe: each per-finding review takes a PostgreSQL advisory
  transaction lock, so two simultaneous passes cannot both review the same
  finding or reserve budget twice. The advisory lock is session-scoped, never
  a row lock, and contends only with other review passes for the same finding.
  On SQLite (single-process development) the lock is skipped by design.
- Fail-isolated: per-finding failures are caught, recorded with fixed reason
  tokens (never raw errors, prompts, or exception chains), and persisted as
  veritas_review_failed diagnostics on their own sessions. Consent, provider
  and the auto flag are re-read immediately before each review, not once per
  pass. The pass never changes the scan's HTTP result.
"""
from __future__ import annotations

import hashlib
from typing import Any

from sqlalchemy import select, text
from sqlalchemy.orm import Session

from ..adapters.events import SqlEventStore
from ..adapters.models import DecisionRow, FindingRow, InvestigationRow
from .model_provider import (
    ModelBudgetExceeded,
    ModelConsentRequired,
    ModelOutputInvalid,
    ModelProviderError,
)
from .veritas import AGENT as VERITAS_AGENT
from .veritas import _decision_references_finding, VeritasReviewService

DETERMINISTIC_PRODUCERS = frozenset({"SPECTRE", "NEXUS"})
SENTINEL_PRODUCER_MODEL_ID = "deterministic-pipeline"
MAX_AUTO_REVIEWS_PER_RUN = 10
REVIEW_ACTION = "review_finding"
FAILURE_EVENT = "veritas_review_failed"

_SUMMARY_KEYS = ("attempted", "completed", "failed", "skipped")


def _lock_key(investigation_id: str, finding_id: str) -> int:
    digest = hashlib.sha256(f"veritas-auto:{investigation_id}:{finding_id}".encode("utf-8")).digest()
    return int.from_bytes(digest[:8], "big", signed=True)


def _already_reviewed(session: Session, investigation_id: str, finding_id: str) -> bool:
    rows = session.execute(
        select(DecisionRow).where(
            DecisionRow.investigation_id == investigation_id,
            DecisionRow.agent == VERITAS_AGENT,
            DecisionRow.action == REVIEW_ACTION,
        )
    ).scalars().all()
    return any(_decision_references_finding(row, finding_id) for row in rows)


def _skip(summary: dict[str, Any], finding_id: str, reason: str) -> None:
    summary["skipped"] += 1
    summary["skips"].append({"finding_id": finding_id, "reason": reason})


def _fail(summary: dict[str, Any], session_factory, investigation_id: str, finding_id: str, reason: str) -> None:
    summary["failed"] += 1
    summary["failures"].append({"finding_id": finding_id, "reason": reason})
    # Persist the failure on its own session/transaction so a rolled-back review
    # can never take the diagnostic down with it. Fixed tokens only - raw errors
    # may carry model output or transport detail and never leave the server.
    diag = session_factory()
    try:
        SqlEventStore(diag).emit(
            investigation_id,
            FAILURE_EVENT,
            {
                "finding_id": finding_id,
                "reason": reason,
                "stage": "auto_review",
                "advisory_only": True,
            },
            actor=VERITAS_AGENT,
        )
        diag.commit()
    except Exception:
        diag.rollback()
        summary["diagnostic_persist_failed"] = True
    finally:
        diag.close()


def _review_one(summary: dict[str, Any], session_factory, gateway, investigation_id: str, finding_id: str) -> None:
    session = session_factory()
    try:
        if session.get_bind().dialect.name == "postgresql":
            locked = session.execute(
                text("SELECT pg_try_advisory_xact_lock(:k)"),
                {"k": _lock_key(investigation_id, finding_id)},
            ).scalar()
            if not locked:
                _skip(summary, finding_id, "review-in-progress")
                return
        finding = session.get(FindingRow, finding_id)
        investigation = session.get(InvestigationRow, investigation_id)
        if finding is None or investigation is None:
            _skip(summary, finding_id, "finding-unavailable")
            return
        # Recheck consent, provider and the opt-in flag immediately before this
        # review - never rely on state read at pass start.
        consent = dict(investigation.llm_data_sharing or {})
        if consent.get("enabled") is not True or consent.get("auto_veritas") is not True:
            _skip(summary, finding_id, "consent-missing")
            return
        if gateway is None or consent.get("provider") != gateway.provider.name:
            _skip(summary, finding_id, "provider-mismatch")
            return
        if _already_reviewed(session, investigation_id, finding_id):
            _skip(summary, finding_id, "already-reviewed")
            return
        if (
            (finding.discovered_by or "").strip().upper() not in DETERMINISTIC_PRODUCERS
            or not list(finding.evidence_refs or [])
        ):
            _skip(summary, finding_id, "provenance-missing")
            return
        summary["attempted"] += 1
        try:
            VeritasReviewService(
                session,
                gateway=gateway,
                session_factory=session_factory,
            ).review(finding_id, producer_model_id=SENTINEL_PRODUCER_MODEL_ID)
            session.commit()
        except ModelConsentRequired:
            session.rollback()
            _fail(summary, session_factory, investigation_id, finding_id, "consent-missing")
        except ModelBudgetExceeded:
            session.rollback()
            _fail(summary, session_factory, investigation_id, finding_id, "budget-exhausted")
        except (ModelOutputInvalid, ValueError):
            session.rollback()
            _fail(summary, session_factory, investigation_id, finding_id, "output-invalid")
        except ModelProviderError:
            session.rollback()
            _fail(summary, session_factory, investigation_id, finding_id, "provider-error")
        except Exception:
            session.rollback()
            _fail(summary, session_factory, investigation_id, finding_id, "review-pass-error")
        else:
            summary["completed"] += 1
    finally:
        session.close()


def run_auto_review_pass(
    *,
    session_factory,
    gateway,
    investigation_id: str,
    max_reviews: int = MAX_AUTO_REVIEWS_PER_RUN,
) -> dict[str, Any]:
    """Review each confirmed, unreviewed, deterministically-produced finding once.

    Returns a fixed-shape summary with counts and fixed reason tokens only.
    """
    summary: dict[str, Any] = {
        "attempted": 0,
        "completed": 0,
        "failed": 0,
        "skipped": 0,
        "failures": [],
        "skips": [],
        "advisory_only": True,
    }
    session = session_factory()
    try:
        finding_ids = [
            row.id
            for row in session.execute(
                select(FindingRow)
                .where(
                    FindingRow.investigation_id == investigation_id,
                    FindingRow.status == "confirmed",
                )
                .order_by(FindingRow.created_at.asc(), FindingRow.id.asc())
            ).scalars()
        ]
    finally:
        session.close()
    for finding_id in finding_ids:
        if summary["attempted"] >= max_reviews:
            _skip(summary, finding_id, "run-cap-reached")
            continue
        _review_one(summary, session_factory, gateway, investigation_id, finding_id)
    return summary
