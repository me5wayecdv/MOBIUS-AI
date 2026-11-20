"""Atomic, cumulative model-token reservations for one investigation.

A reservation is committed before network/provider work begins. The investigation row is
updated under a database write lock (SQLite) / row lock (PostgreSQL), so concurrent calls
cannot each spend the same stale remaining-budget snapshot. Reservations are reconciled to
provider-reported usage after each call.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from uuid import uuid4

from sqlalchemy import update
from sqlalchemy.orm import sessionmaker

from ..adapters.events import SqlEventStore
from ..adapters.models import InvestigationRow
from .model_provider import ModelBudgetExceeded


@dataclass(frozen=True, slots=True)
class TokenReservation:
    investigation_id: str
    reservation_id: str
    reserved_tokens: int
    budget_limit: int


class InvestigationTokenBudget:
    def __init__(self, session_factory: sessionmaker) -> None:
        self.session_factory = session_factory

    def reserve(self, investigation_id: str, tokens: int) -> TokenReservation:
        if tokens <= 0:
            raise ValueError("token reservation must be positive")
        session = self.session_factory()
        try:
            # A no-op UPDATE acquires a write/row lock before reading JSON counters.
            result = session.execute(
                update(InvestigationRow)
                .where(InvestigationRow.id == investigation_id)
                .values(used_json=InvestigationRow.used_json)
            )
            if result.rowcount != 1:
                raise ModelBudgetExceeded("investigation does not exist for token reservation")
            session.expire_all()
            row = session.get(InvestigationRow, investigation_id)
            used: dict[str, Any] = dict(row.used_json or {})
            budget = dict(row.budget_json or {})
            limit = int(budget.get("max_model_tokens", 0))
            actual = int(used.get("model_tokens", 0))
            reserved = int(used.get("model_tokens_reserved", 0))
            if actual + reserved + tokens > limit:
                raise ModelBudgetExceeded(
                    f"investigation token budget would be exceeded: "
                    f"{actual} used + {reserved} reserved + {tokens} requested > {limit}"
                )
            used["model_tokens_reserved"] = reserved + tokens
            row.used_json = used
            reservation = TokenReservation(
                investigation_id=investigation_id,
                reservation_id=str(uuid4()),
                reserved_tokens=tokens,
                budget_limit=limit,
            )
            session.commit()
            return reservation
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    def settle(
        self,
        reservation: TokenReservation,
        *,
        actual_tokens: int,
        provider: str,
        model_id: str,
        usage: dict[str, Any] | None = None,
    ) -> None:
        if actual_tokens < 0:
            raise ValueError("actual token usage cannot be negative")
        session = self.session_factory()
        try:
            result = session.execute(
                update(InvestigationRow)
                .where(InvestigationRow.id == reservation.investigation_id)
                .values(used_json=InvestigationRow.used_json)
            )
            if result.rowcount != 1:
                raise ModelBudgetExceeded("investigation disappeared during token settlement")
            session.expire_all()
            row = session.get(InvestigationRow, reservation.investigation_id)
            used: dict[str, Any] = dict(row.used_json or {})
            current_reserved = int(used.get("model_tokens_reserved", 0))
            if current_reserved < reservation.reserved_tokens:
                raise ModelBudgetExceeded("token reservation ledger is inconsistent")
            current_used = int(used.get("model_tokens", 0))
            remaining_reserved = current_reserved - reservation.reserved_tokens
            if actual_tokens > reservation.reserved_tokens:
                # Do not silently accept a provider whose reported usage exceeds the
                # pre-call upper bound. Consume the full reservation and fail closed.
                used["model_tokens_reserved"] = remaining_reserved
                used["model_tokens"] = current_used + reservation.reserved_tokens
                row.used_json = used
                # The ledger charge stays the conservative full reservation; the
                # audit event must also retain the provider's true measured usage
                # (when supplied) so an overrun review sees reality, not the sentinel.
                payload = {"provider": provider, "model_id": model_id,
                           "reserved_tokens": reservation.reserved_tokens,
                           "reported_tokens": actual_tokens}
                if usage:
                    payload.update(usage)
                SqlEventStore(session).emit(
                    row.id, "model_budget_rejected",
                    payload,
                    actor="NEXUS",
                )
                session.commit()
                raise ModelBudgetExceeded("provider-reported usage exceeded the reserved token ceiling")
            total = current_used + actual_tokens
            if total + remaining_reserved > reservation.budget_limit:
                raise ModelBudgetExceeded("settled model usage would exceed the investigation budget")
            used["model_tokens_reserved"] = remaining_reserved
            used["model_tokens"] = total
            row.used_json = used
            SqlEventStore(session).emit(
                row.id, "model_tokens_consumed",
                {"provider": provider, "model_id": model_id,
                 "input_and_output_tokens": actual_tokens,
                 "cumulative_tokens": total,
                 "reserved_tokens_remaining": remaining_reserved,
                 "budget_limit": reservation.budget_limit},
                actor="NEXUS",
            )
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    def release(self, reservation: TokenReservation) -> None:
        """Release a reservation only when no provider usage was returned."""
        session = self.session_factory()
        try:
            session.execute(
                update(InvestigationRow)
                .where(InvestigationRow.id == reservation.investigation_id)
                .values(used_json=InvestigationRow.used_json)
            )
            session.expire_all()
            row = session.get(InvestigationRow, reservation.investigation_id)
            if row is None:
                raise ModelBudgetExceeded("investigation disappeared while releasing reservation")
            used: dict[str, Any] = dict(row.used_json or {})
            current = int(used.get("model_tokens_reserved", 0))
            if current < reservation.reserved_tokens:
                raise ModelBudgetExceeded("token reservation ledger is inconsistent")
            used["model_tokens_reserved"] = current - reservation.reserved_tokens
            row.used_json = used
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()
