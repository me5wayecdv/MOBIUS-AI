"""Allowlisted, non-destructive PoC adapters (D-041).

This runner never spawns processes, invokes shell commands, or contacts the network.
It supports read-only checks against persisted manifest observations and two explicitly
named in-process local harnesses. Emulator execution remains unavailable until a verified
emulator adapter and host capability are supplied.
"""
from __future__ import annotations

import json
import hashlib
from dataclasses import dataclass
from datetime import datetime, timezone
import time
from typing import Any, Callable
from urllib.parse import urlsplit

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..adapters.models import (
    ApplicationRow, AuthorizationRow, ApprovalRow, HypothesisRow, InvestigationRow, ObservationRow,
)
from ..adapters.events import utcnow
from ..core.schemas import PoCTestPlan


class PoCExecutionError(RuntimeError):
    """The requested proof cannot safely run."""


class PoCScopeRejected(PoCExecutionError):
    """The plan is not bound to the investigation's current authorization and APK."""


class PoCAdapterUnavailable(PoCExecutionError):
    """No approved adapter exists for this target kind/action."""


class PoCApprovalRequired(PoCExecutionError):
    """The plan requires a future approval workflow that is not part of D-041."""


@dataclass(frozen=True, slots=True)
class PoCStepResult:
    index: int
    action: str
    target_ref: str
    status: str
    passed: bool
    actual_value: Any
    expected_value: Any
    duration_ms: int
    tool_name: str
    tool_version: str
    detail: str = ""


@dataclass(frozen=True, slots=True)
class PoCExecutionResult:
    plan_id: str
    investigation_id: str
    target_sha256: str
    status: str
    started_at: str
    finished_at: str
    duration_ms: int
    steps: tuple[PoCStepResult, ...]
    output_json: dict[str, Any]
    tool_versions: tuple[str, ...]
    limitations: tuple[str, ...]
    cleanup_results: tuple[dict[str, Any], ...]


class SafePoCRunner:
    """Runs only typed, scope-checked read-only/local-harness plans."""

    VERSION = "mobius-safe-poc/0.1.0"
    _HARNESS_VERSION = "mobius-local-harness/1.0.0"

    def __init__(self, session: Session, emulator_adapter=None) -> None:
        self.session = session
        # Optional PHANTOM adapter (services/phantom.py). Duck-typed on
        # purpose: poc_runner must not import phantom (phantom imports the
        # runner's error types). None preserves the historical fail-closed
        # behavior for emulator-target plans.
        self._emulator_adapter = emulator_adapter
        self._harnesses: dict[str, Callable[[dict[str, str | bool | int]], dict[str, Any]]] = {
            "unsafe_webview_forwarder_v1": self._unsafe_webview_forwarder,
            "safe_webview_guard_v1": self._safe_webview_guard,
        }

    def run(self, plan: PoCTestPlan, *, cancel_check: Callable[[], bool] | None = None) -> PoCExecutionResult:
        self.validate_authority(plan)
        if plan.target_kind == "native_local_fixture":
            raise PoCAdapterUnavailable("native fixture requires its separately configured host boundary")
        if plan.target_kind == "emulator" and self._emulator_adapter is None:
            raise PoCAdapterUnavailable("no verified Android emulator adapter is configured on this host")
        if plan.cleanup_steps and plan.target_kind != "local_harness":
            emulator_cleanup_ok = (
                plan.target_kind == "emulator"
                and all(c.action == "stop_emulator_instrumentation" for c in plan.cleanup_steps)
            )
            if not emulator_cleanup_ok:
                raise PoCAdapterUnavailable(
                    "cleanup adapters are limited to local_harness targets and "
                    "emulator instrumentation stops"
                )

        started_clock = time.monotonic()
        started_at = utcnow()
        context: dict[str, Any] = {}
        results: list[PoCStepResult] = []
        cleanup_results: list[dict[str, Any]] = []
        versions: set[str] = set()
        status = "passed"
        try:
            for index, step in enumerate(plan.steps):
                if cancel_check is not None and cancel_check():
                    status = "cancelled"
                    break
                if time.monotonic() - started_clock >= plan.max_duration_seconds:
                    status = "timed_out"
                    break
                step_started = time.monotonic()
                if plan.target_kind == "lab_apk":
                    actual, tool, version, detail = self._run_manifest_step(plan, step.action, step.target_ref)
                elif plan.target_kind == "local_harness":
                    actual, tool, version, detail = self._run_harness_step(step.action, step.target_ref, step.input_values, context)
                elif plan.target_kind == "emulator":
                    actual, tool, version, detail = self._run_emulator_step(plan, step)
                else:
                    raise PoCAdapterUnavailable(f"unsupported target kind: {plan.target_kind}")
                versions.add(f"{tool}/{version}")
                if step.action in {
                    "assert_manifest_component", "assert_manifest_permission", "assert_local_harness_result",
                    "assert_emulator_package_present",
                }:
                    passed = actual == step.expected_value
                elif step.action in {"assert_emulator_provider_rows", "assert_emulator_frida_classes"}:
                    # Documented threshold semantics: the runtime probe proves
                    # at least the expected count is observed. A failed or
                    # refused probe (actual None) never passes.
                    passed = (
                        isinstance(actual, int) and not isinstance(actual, bool)
                        and isinstance(step.expected_value, int)
                        and not isinstance(step.expected_value, bool)
                        and actual >= step.expected_value
                    )
                else:
                    passed = True
                duration_ms = max(0, int((time.monotonic() - step_started) * 1000))
                results.append(PoCStepResult(index=index, action=step.action, target_ref=step.target_ref,
                    status="passed" if passed else "failed", passed=passed, actual_value=actual,
                    expected_value=step.expected_value, duration_ms=duration_ms, tool_name=tool, tool_version=version,
                    detail=detail))
                if duration_ms > step.timeout_seconds * 1000 or time.monotonic() - started_clock > plan.max_duration_seconds:
                    status = "timed_out"
                    break
                if not passed:
                    status = "failed"
                    break
        finally:
            for cleanup in plan.cleanup_steps:
                cleanup_started = time.monotonic()
                if cleanup.action == "reset_local_harness":
                    context.clear()
                    cleanup_status = "completed"
                    detail = "in-memory harness context reset"
                elif cleanup.action == "remove_temporary_workspace":
                    cleanup_status = "completed"
                    detail = "no temporary workspace was created by the in-process harness"
                elif cleanup.action == "stop_emulator_instrumentation":
                    if self._emulator_adapter is None:
                        cleanup_status = "unavailable"
                        detail = "no emulator adapter is configured"
                    else:
                        detail = self._emulator_adapter.stop_instrumentation()
                        cleanup_status = "completed"
                else:
                    cleanup_status = "unavailable"
                    detail = "cleanup action is not registered"
                cleanup_results.append({"action": cleanup.action, "target_ref": cleanup.target_ref,
                    "status": cleanup_status, "detail": detail,
                    "duration_ms": max(0, int((time.monotonic() - cleanup_started) * 1000))})

        finished_at = utcnow()
        total_ms = max(0, int((time.monotonic() - started_clock) * 1000))
        output = {"plan_id": plan.id, "target_sha256": plan.target_sha256,
            "steps": [{"index": r.index, "action": r.action, "target_ref": r.target_ref,
                "status": r.status, "passed": r.passed, "actual_value": r.actual_value,
                "expected_value": r.expected_value, "tool": r.tool_name, "tool_version": r.tool_version}
                for r in results],
            "cleanup": cleanup_results, "simulation_only": plan.target_kind == "local_harness"}
        encoded = json.dumps(output, sort_keys=True, default=str).encode("utf-8")
        if len(encoded) > plan.max_output_bytes:
            raise PoCExecutionError("PoC output exceeds the plan's max_output_bytes")
        if status == "passed" and not results:
            status = "failed"
        return PoCExecutionResult(plan_id=plan.id, investigation_id=plan.investigation_id,
            target_sha256=plan.target_sha256, status=status, started_at=started_at, finished_at=finished_at,
            duration_ms=total_ms, steps=tuple(results), output_json=output, tool_versions=tuple(sorted(versions)),
            limitations=(
                (self._emulator_limitation(plan)
                 if plan.target_kind == "emulator" else
                 "Local harness results are deterministic simulations, not execution of the APK."),
                ("No shell, network, or state-changing action is available."
                 if plan.target_kind == "emulator" else
                 "No shell, subprocess, network, emulator, or state-changing action is available."),
                "Cancellation is cooperative between bounded allowlisted steps; it cannot interrupt a running step."),
            cleanup_results=tuple(cleanup_results))

    def validate_authority(self, plan: PoCTestPlan) -> None:
        self._validate_scope(plan)
        if plan.safety_class == "state_changing":
            raise PoCExecutionError("state-changing actions remain disabled; no state-changing adapter is registered")
        if plan.requires_approval:
            approval = self.session.get(ApprovalRow, plan.approval_id) if plan.approval_id else None
            if (approval is None or approval.investigation_id != plan.investigation_id
                or approval.requested_action != "poc.execute" or approval.state != "granted"
                or approval.plan_sha256 != hashlib.sha256(json.dumps(
                    plan.model_dump(mode="json", exclude={"approval_id"}),
                    sort_keys=True, separators=(",", ":"),
                ).encode("utf-8")).hexdigest()
                or datetime.fromisoformat(approval.expires_at.replace("Z", "+00:00")) <= datetime.now(timezone.utc)):
                raise PoCApprovalRequired("a matching, unexpired granted PoC approval is required")
        elif plan.safety_class != "read_only":
            raise PoCApprovalRequired("non-read-only plans require explicit approval")

    def _validate_scope(self, plan: PoCTestPlan) -> None:
        investigation = self.session.get(InvestigationRow, plan.investigation_id)
        if investigation is None:
            raise PoCScopeRejected("investigation does not exist")
        if investigation.authorization_id != plan.authorization_id:
            raise PoCScopeRejected("plan authorization does not match the investigation")
        authorization = self.session.get(AuthorizationRow, plan.authorization_id)
        if authorization is None:
            raise PoCScopeRejected("authorization does not exist")
        application = self.session.get(ApplicationRow, investigation.application_id)
        if application is None:
            raise PoCScopeRejected("investigation application does not exist")
        if (
            application.sha256 != plan.target_sha256
            or authorization.apk_sha256 != plan.target_sha256
            or authorization.target_package != plan.target_package
            or (application.package_name is not None and application.package_name != plan.target_package)
        ):
            raise PoCScopeRejected("plan target identity does not match authorized APK")
        if authorization.revoked_at is not None:
            raise PoCScopeRejected("authorization has been revoked")
        expiry = datetime.fromisoformat(authorization.expires_at.replace("Z", "+00:00"))
        if expiry <= datetime.now(timezone.utc):
            raise PoCScopeRejected("authorization has expired")
        if investigation.intensity > authorization.max_intensity:
            raise PoCScopeRejected("investigation intensity exceeds authorization")
        if investigation.state in {"CLOSED", "CANCELLED", "FAILED"}:
            raise PoCScopeRejected("investigation is not in an executable state")
        hypotheses = set(self.session.execute(
            select(HypothesisRow.id).where(
                HypothesisRow.investigation_id == plan.investigation_id,
                HypothesisRow.id.in_(plan.hypothesis_ids),
            )
        ).scalars())
        if hypotheses != set(plan.hypothesis_ids):
            raise PoCScopeRejected("one or more hypotheses do not belong to this investigation")

    def _run_manifest_step(self, plan: PoCTestPlan, action: str, target_ref: str):
        if action == "assert_manifest_component":
            found = self.session.execute(
                select(ObservationRow.id).where(
                    ObservationRow.investigation_id == plan.investigation_id,
                    ObservationRow.subject_type == "component",
                    ObservationRow.subject_ref == target_ref,
                    ObservationRow.kind == "fact",
                ).limit(1)
            ).scalar_one_or_none()
            return found is not None, "persisted-manifest-observation", "1", "persisted manifest fact lookup"
        if action == "assert_manifest_permission":
            rows = self.session.execute(
                select(ObservationRow).where(
                    ObservationRow.investigation_id == plan.investigation_id,
                    ObservationRow.subject_type == "component",
                )
            ).scalars()
            declared = any((row.attributes or {}).get("permission") == target_ref for row in rows)
            return declared, "persisted-manifest-observation", "1", "persisted manifest fact lookup"
        raise PoCAdapterUnavailable(f"action {action} is not available for lab_apk targets")

    @staticmethod
    def _emulator_limitation(plan: PoCTestPlan) -> str:
        if any(step.action == "assert_emulator_frida_classes" for step in plan.steps):
            return ("Observation-only Frida instrumentation attached to the lab app on a "
                    "verified emulator under an approved plan; no method tampering; "
                    "instrumentation was stopped by the cleanup step; no proxy capability exists.")
        return ("Emulator probes ran read-only via adb against a verified emulator; physical "
                "devices are refused; no install, delete, Frida or proxy capability exists.")

    def _run_emulator_step(self, plan: PoCTestPlan, step):
        adapter = self._emulator_adapter
        if adapter is None:
            raise PoCAdapterUnavailable("no verified Android emulator adapter is configured on this host")
        if step.action == "assert_emulator_package_present":
            if step.target_ref != plan.target_package:
                raise PoCScopeRejected(
                    "emulator package probes must target the plan's authorized package"
                )
            result = adapter.probe_package_present(step.target_ref)
            return result.actual, "phantom-adb", adapter.VERSION, result.detail
        if step.action == "assert_emulator_provider_rows":
            authority, sep, path = step.target_ref.partition("/")
            if (
                not sep or not path or "/" in path
                or authority == plan.target_package
                or not authority.startswith(plan.target_package + ".")
            ):
                raise PoCScopeRejected(
                    "emulator provider probes must target one authority path "
                    "within the plan's authorized package"
                )
            result = adapter.probe_provider_query_rows(authority, path)
            return result.actual, "phantom-adb", adapter.VERSION, result.detail
        if step.action == "assert_emulator_frida_classes":
            if step.target_ref != plan.target_package:
                raise PoCScopeRejected(
                    "emulator instrumentation probes must target the plan's authorized package"
                )
            result = adapter.probe_frida_enumerate_classes(step.target_ref)
            return result.actual, "phantom-frida", adapter.VERSION, result.detail
        raise PoCAdapterUnavailable(f"action {step.action} is not available for emulator targets")

    def _run_harness_step(
        self,
        action: str,
        target_ref: str,
        input_values: dict[str, str | bool | int],
        context: dict[str, Any],
    ):
        if action == "invoke_local_harness":
            harness = self._harnesses.get(target_ref)
            if harness is None:
                raise PoCAdapterUnavailable(f"local harness is not registered: {target_ref}")
            result = harness(input_values)
            context["last_result"] = result
            return result, target_ref, self._HARNESS_VERSION, "deterministic local harness"
        if action == "assert_local_harness_result":
            result = context.get("last_result")
            if not isinstance(result, dict):
                raise PoCExecutionError("no local harness result is available to assert")
            actual = result.get(target_ref)
            return actual, "local-harness-assertion", self._HARNESS_VERSION, "deterministic local harness"
        raise PoCAdapterUnavailable(f"action {action} is not available for local_harness targets")

    @staticmethod
    def _unsafe_webview_forwarder(values: dict[str, str | bool | int]) -> dict[str, Any]:
        url = values.get("url")
        if not isinstance(url, str) or not url or len(url) > 2048:
            raise PoCExecutionError("unsafe_webview_forwarder requires a bounded url string")
        parsed = urlsplit(url)
        return {
            "source": "intent_extra",
            "sink_invoked": True,
            "forwarded_url": url,
            "scheme": parsed.scheme.lower(),
            "simulation": True,
        }

    @staticmethod
    def _safe_webview_guard(values: dict[str, str | bool | int]) -> dict[str, Any]:
        url = values.get("url")
        if not isinstance(url, str) or not url or len(url) > 2048:
            raise PoCExecutionError("safe_webview_guard requires a bounded url string")
        parsed = urlsplit(url)
        allowed = parsed.scheme.lower() in {"https"} and parsed.hostname == "trusted.example"
        return {
            "source": "intent_extra",
            "sink_invoked": allowed,
            "blocked": not allowed,
            "scheme": parsed.scheme.lower(),
            "simulation": True,
        }
