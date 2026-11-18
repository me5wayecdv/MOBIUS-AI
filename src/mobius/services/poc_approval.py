"""Persisted approval decisions for bounded PoC plans (D-043)."""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
from sqlalchemy.orm import Session

from ..adapters.events import SqlEventStore, utcnow
from ..adapters.models import ApprovalRow
from ..core.ids import IdPrefix, new_id
from ..core.schemas import PoCTestPlan


class PoCApprovalError(ValueError):
    pass


class PoCApprovalService:
    def __init__(self, session: Session) -> None:
        self.session = session

    def request(self, plan: PoCTestPlan, *, requested_by: str, justification: str,
                risk_summary: str, expires_at: str) -> ApprovalRow:
        if not plan.requires_approval or plan.safety_class == "read_only":
            raise PoCApprovalError("approval requests are only valid for non-read-only plans")
        expiry = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
        if expiry <= datetime.now(timezone.utc):
            raise PoCApprovalError("approval expiry must be in the future")
        plan_sha256 = hashlib.sha256(json.dumps(
            plan.model_dump(mode="json", exclude={"approval_id"}),
            sort_keys=True, separators=(",", ":"),
        ).encode("utf-8")).hexdigest()
        row = ApprovalRow(
            id=new_id(IdPrefix.APPROVAL), investigation_id=plan.investigation_id,
            requested_action="poc.execute", plan_sha256=plan_sha256,
            intensity_required=1, intensity_granted=None,
            justification=justification, risk_summary=risk_summary, state="pending",
            requested_by=requested_by, decided_by=None, decided_at=None, decision_note=None,
            expires_at=expires_at, created_at=utcnow(),
        )
        self.session.add(row)
        self.session.flush()
        SqlEventStore(self.session).emit(plan.investigation_id, "approval_requested", {
            "approval_id": row.id, "plan_id": plan.id, "action": "poc.execute",
            "safety_class": plan.safety_class, "expires_at": expires_at,
            "risk_summary": risk_summary,
        }, actor=requested_by)
        return row

    def resolve(self, approval_id: str, *, investigation_id: str, decision: str,
                decided_by: str, note: str) -> ApprovalRow:
        row = self.session.get(ApprovalRow, approval_id)
        if row is None or row.investigation_id != investigation_id or row.requested_action != "poc.execute":
            raise PoCApprovalError("PoC approval not found")
        if row.state != "pending":
            raise PoCApprovalError(f"approval is already {row.state}")
        if datetime.fromisoformat(row.expires_at.replace("Z", "+00:00")) <= datetime.now(timezone.utc):
            row.state = "expired"
            row.decided_at = utcnow()
            row.decision_note = "Approval request expired before decision"
            SqlEventStore(self.session).emit(investigation_id, "approval_resolved", {
                "approval_id": row.id, "decision": "expired",
            }, actor=decided_by)
            return row
        if decision not in {"granted", "rejected"}:
            raise PoCApprovalError("decision must be granted or rejected")
        row.state = decision
        row.intensity_granted = row.intensity_required if decision == "granted" else None
        row.decided_at = utcnow()
        row.decision_note = note
        SqlEventStore(self.session).emit(investigation_id, "approval_resolved", {
            "approval_id": row.id, "decision": decision, "note": note,
        }, actor=decided_by)
        return row

    def cancel(self, approval_id: str, *, investigation_id: str, cancelled_by: str) -> ApprovalRow:
        row = self.session.get(ApprovalRow, approval_id)
        if row is None or row.investigation_id != investigation_id or row.requested_action != "poc.execute":
            raise PoCApprovalError("PoC approval not found")
        if row.state != "pending":
            raise PoCApprovalError(f"approval is already {row.state}")
        row.state = "revoked"
        row.decided_at = utcnow()
        row.decision_note = "Cancelled by requester"
        SqlEventStore(self.session).emit(investigation_id, "approval_resolved", {
            "approval_id": row.id, "decision": "revoked",
        }, actor=cancelled_by)
        return row
