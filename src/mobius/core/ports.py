"""Ports: the interfaces Layer 1 depends on and Layer 2 implements.

These live in ``core/`` and nowhere else. An earlier draft of the architecture parked
``ModelGateway`` under ``adapters/`` while a core contract imported it, which inverted the
dependency and made the import-lint rule unenforceable (review finding I-03, ADR-017
context). Ports belong to the layer that *uses* them, which is the domain.

Nothing here imports a framework, a driver or a vendor SDK.
"""

from __future__ import annotations

from typing import Any, Protocol, Sequence, runtime_checkable

from pydantic import BaseModel

from .schemas import Evidence, FrontierEntry, ToolExecution


@runtime_checkable
class EvidenceReader(Protocol):
    """Read-only access to stored artefacts. Deliberately cannot write."""

    def get(self, evidence_id: str) -> Evidence: ...

    def read_text(self, evidence_id: str, *, max_bytes: int = 65_536) -> str: ...

    def find_by_kind(self, kind: str, *, limit: int = 100) -> Sequence[Evidence]: ...


@runtime_checkable
class ToolInvoker(Protocol):
    """Runs a tool by name with validated arguments.

    There is no method that accepts a command string. A tool's binary path comes from
    server configuration, never from the caller and never from a model, so no capability
    exists that could turn a string into argv (NFR-SEC-1).
    """

    def invoke(
        self, tool: str, args: BaseModel, *, timeout_s: int | None = None
    ) -> ToolExecution: ...

    def is_available(self, tool: str) -> bool: ...


@runtime_checkable
class ModelGateway(Protocol):
    """Structured completion. Returns a validated instance or a deterministic failure.

    Absent on purpose: streaming, tool-calling, vision, function schemas. Each is a
    capability that must be *measured* before it is *relied on*.
    """

    async def complete_structured(
        self,
        *,
        role: str,
        system: str,
        user: str,
        schema: type[BaseModel],
        temperature: float = 0.0,
        max_tokens: int = 4096,
    ) -> Any: ...


@runtime_checkable
class EventEmitter(Protocol):
    """Appends a forensic event. The only sanctioned way to record a state change."""

    def emit(
        self,
        event_type: str,
        payload: dict[str, Any],
        *,
        actor: str,
        causation_id: str | None = None,
        correlation_id: str | None = None,
    ) -> int:
        """Return the allocated sequence number."""
        ...


@runtime_checkable
class BudgetMeter(Protocol):
    def remaining(self, resource: str) -> int: ...

    def consume(self, resource: str, amount: int = 1) -> None: ...


@runtime_checkable
class FrontierQueue(Protocol):
    def push(self, entry: FrontierEntry) -> None: ...

    def pop_best(self) -> FrontierEntry | None: ...

    def pending_count(self) -> int: ...
