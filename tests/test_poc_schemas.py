import pytest
from pydantic import ValidationError

from mobius.core.schemas import PoCTestPlan


def _plan(**overrides):
    values = {
        "investigation_id": "scn_fixture",
        "authorization_id": "aut_fixture",
        "target_sha256": "a" * 64,
        "target_package": "com.example.lab",
        "target_kind": "lab_apk",
        "hypothesis_ids": ("hyp_fixture",),
        "prerequisites": ("component is exported",),
        "steps": (
            {"action": "assert_manifest_component", "target_ref": "com.example.Entry",
             "expected_value": True, "timeout_seconds": 10},
            {"action": "assert_manifest_permission", "target_ref": "android.permission.READ_SMS",
             "expected_value": False, "timeout_seconds": 10},
        ),
        "expected_outcome": "The exported component has no declared permission.",
        "safety_class": "read_only",
        "max_duration_seconds": 30,
        "max_output_bytes": 4096,
    }
    values.update(overrides)
    return values


def test_poc_plan_is_typed_scoped_and_budgeted():
    plan = PoCTestPlan(**_plan())
    assert plan.id.startswith("poc_")
    assert plan.target_sha256 == "a" * 64
    assert len(plan.steps) == 2


def test_poc_plan_rejects_arbitrary_actions_and_invalid_target_digest():
    with pytest.raises(ValidationError):
        PoCTestPlan(**_plan(steps=({"action": "run_shell", "target_ref": "id"} ,)))
    with pytest.raises(ValidationError):
        PoCTestPlan(**_plan(target_sha256="not-a-digest"))


def test_poc_plan_enforces_total_budget():
    with pytest.raises(ValidationError, match="sum of step timeouts"):
        PoCTestPlan(**_plan(max_duration_seconds=10))


def test_state_changing_plan_requires_approval_and_cleanup():
    with pytest.raises(ValidationError, match="require explicit approval"):
        PoCTestPlan(**_plan(safety_class="state_changing"))
    with pytest.raises(ValidationError, match="cleanup_steps"):
        PoCTestPlan(**_plan(
            safety_class="non_destructive",
            cleanup_steps=(),
        ))


def test_local_harness_cannot_use_manifest_actions():
    with pytest.raises(ValidationError, match="manifest assertions"):
        PoCTestPlan(**_plan(target_kind="local_harness"))
