"""Closed, typed action registry for NEXUS.

The model may propose an action name and JSON arguments in later planner slices, but this
registry is the authority. It contains no shell/argv field and cannot resolve arbitrary
binaries or targets.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError


class ActionRejected(ValueError):
    pass


class _ActionArgs(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class ComponentArgs(_ActionArgs):
    component: str = Field(
        min_length=1,
        max_length=500,
        pattern=r"^[A-Za-z_$][A-Za-z0-9_.$]*$",
    )
    source: Literal["manifest"] | None = None


@dataclass(frozen=True, slots=True)
class ActionSpec:
    name: str
    agent: str
    args_model: type[BaseModel]
    minimum_intensity: int
    description: str


_REGISTRY: dict[str, ActionSpec] = {
    "find_api_refs": ActionSpec(
        name="find_api_refs",
        agent="SPECTRE",
        args_model=ComponentArgs,
        minimum_intensity=0,
        description="Inspect the indexed call graph for a named application component.",
    ),
    "callers_of": ActionSpec(
        name="callers_of",
        agent="SPECTRE",
        args_model=ComponentArgs,
        minimum_intensity=0,
        description="Inspect caller relationships for a named application component.",
    ),
}


class ActionRegistry:
    """Immutable allowlist plus strict argument and authorization policy validation."""

    def __init__(self, specs: dict[str, ActionSpec] | None = None) -> None:
        selected = dict(_REGISTRY if specs is None else specs)
        if any(name != spec.name for name, spec in selected.items()):
            raise ValueError("action registry keys must match their action names")
        if len(selected) != len(set(selected)):
            raise ValueError("duplicate action registry entry")
        self._specs = selected

    @property
    def names(self) -> tuple[str, ...]:
        return tuple(sorted(self._specs))

    def describe(self) -> list[dict[str, Any]]:
        return [
            {
                "name": spec.name,
                "agent": spec.agent,
                "minimum_intensity": spec.minimum_intensity,
                "description": spec.description,
                "arguments_schema": spec.args_model.model_json_schema(),
            }
            for spec in sorted(self._specs.values(), key=lambda item: item.name)
        ]

    def validate(
        self,
        action: str,
        args: dict[str, Any],
        *,
        required_agent: str,
        intensity: int,
    ) -> tuple[ActionSpec, dict[str, Any]]:
        spec = self._specs.get(action)
        if spec is None:
            raise ActionRejected(f"action {action!r} is not registered")
        if required_agent != spec.agent:
            raise ActionRejected(
                f"action {action!r} is assigned to {required_agent!r}, expected {spec.agent!r}"
            )
        if intensity < spec.minimum_intensity:
            raise ActionRejected(
                f"action {action!r} requires intensity {spec.minimum_intensity}"
            )
        if not isinstance(args, dict):
            raise ActionRejected("action arguments must be a JSON object")
        try:
            parsed = spec.args_model.model_validate(args)
        except ValidationError as exc:
            raise ActionRejected(f"invalid arguments for {action}: {exc.errors(include_url=False)}") from exc
        return spec, parsed.model_dump(mode="json")
