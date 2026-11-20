"""Request/response bodies. Kept separate from domain models so the wire contract can
evolve without changing Layer 1."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class _Base(BaseModel):
    model_config = ConfigDict(extra="forbid")


class AuthorizationCreate(_Base):
    apk_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    target_package: str = Field(min_length=1, max_length=300)
    scope_text: str = Field(min_length=20, max_length=4000)
    statement: str = Field(min_length=1, max_length=2000)
    max_intensity: int = Field(ge=0, le=3)
    expires_at: str


class BudgetIn(_Base):
    max_steps: int = Field(default=60, ge=1)
    max_model_tokens: int = Field(default=400_000, ge=0)
    max_tool_calls: int = Field(default=80, ge=0)
    max_wall_seconds: int = Field(default=1800, ge=1)


class ScanCreate(_Base):
    application_id: str
    authorization_id: str
    objective: str = Field(min_length=10, max_length=2000)
    intensity: int = Field(default=0, ge=0, le=2)
    budget: BudgetIn = Field(default_factory=BudgetIn)
    llm_data_sharing: bool = False


class PauseRequest(_Base):
    reason: str | None = None


class ValidationRequest(_Base):
    """Ask for a gate evaluation over supplied attributes.

    In the full system these attributes come from observations written by SPECTRE and
    PHANTOM. Here they are supplied directly so the gate path is exercisable before the
    analysis agents exist - a seam, not a shortcut: the gate is evaluated exactly as it
    will be later.
    """

    category: str
    attributes: dict[str, Any]
    title: str = Field(min_length=5)
    description: str = Field(min_length=1)
    evidence_refs: tuple[str, ...]
    discovered_by: str = "SPECTRE"
    validated_by: str = "VERITAS"
    component_ref: str | None = None
    rejection_reason: str | None = None



class ModelConsentRequest(_Base):
    enabled: bool
    provider: str | None = Field(default=None, pattern=r"^ollama$")
    # Opt-in for the post-investigation advisory VERITAS auto-review pass.
    # Default-off; requires enabled consent. Advisory only - deterministic
    # gates remain the sole verdict authority either way.
    auto_veritas: bool = False


class PoCApprovalRequest(_Base):
    plan: dict[str, Any]
    justification: str = Field(min_length=10, max_length=2000)
    risk_summary: str = Field(min_length=10, max_length=2000)
    expires_at: str


class PoCApprovalDecision(_Base):
    decision: str = Field(pattern=r"^(granted|rejected)$")
    note: str = Field(min_length=1, max_length=2000)
