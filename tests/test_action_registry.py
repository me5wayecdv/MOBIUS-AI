from __future__ import annotations

import pytest

from mobius.core.actions import ActionRegistry, ActionRejected


def test_registry_exposes_only_closed_typed_static_actions():
    registry = ActionRegistry()
    assert registry.names == ("callers_of", "find_api_refs")
    descriptions = registry.describe()
    assert {item["agent"] for item in descriptions} == {"SPECTRE"}
    assert all("command" not in item["arguments_schema"]["properties"] for item in descriptions)


@pytest.mark.parametrize("action", ["__import__", "run_shell", "adb_shell", "http_request", ""])
def test_registry_rejects_unregistered_or_arbitrary_actions(action):
    with pytest.raises(ActionRejected, match="not registered"):
        ActionRegistry().validate(
            action, {"component": "com.example.Entry"},
            required_agent="SPECTRE", intensity=0,
        )


def test_registry_accepts_known_component_action_and_returns_validated_args():
    spec, args = ActionRegistry().validate(
        "find_api_refs",
        {"component": "com.example.Entry$Nested"},
        required_agent="SPECTRE",
        intensity=0,
    )
    assert spec.agent == "SPECTRE"
    assert args == {"component": "com.example.Entry$Nested"}


@pytest.mark.parametrize(
    "args",
    [
        {"component": "com.example.Entry", "command": "id"},
        {"component": "../../etc/passwd"},
        {"component": "https://example.com"},
        {"component": ""},
        [],
        "com.example.Entry",
    ],
)
def test_registry_rejects_extra_or_untrusted_action_arguments(args):
    with pytest.raises(ActionRejected):
        ActionRegistry().validate(
            "find_api_refs", args,
            required_agent="SPECTRE", intensity=0,
        )


def test_registry_rejects_agent_mismatch_and_insufficient_intensity():
    registry = ActionRegistry()
    with pytest.raises(ActionRejected, match="expected"):
        registry.validate(
            "find_api_refs", {"component": "com.example.Entry"},
            required_agent="PHANTOM", intensity=0,
        )
    with pytest.raises(ActionRejected, match="requires intensity"):
        registry.validate(
            "find_api_refs", {"component": "com.example.Entry"},
            required_agent="SPECTRE", intensity=-1,
        )
