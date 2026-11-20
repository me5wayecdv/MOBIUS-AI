"""PHANTOM emulator adapter (D-060 first slice): read-only adb probes.

The adapter's command runner and emulator check are injected, so these tests
never touch a real device. Fail-closed behavior without an adapter is pinned.
"""
from __future__ import annotations

import pytest

from mobius.adapters.models import AuthorizationRow, HypothesisRow
from mobius.core.ids import IdPrefix, new_id
from mobius.core.schemas import PoCStep, PoCTestPlan
from mobius.services.intake import IntakeService
from mobius.services.phantom import PhantomEmulatorAdapter
from mobius.services.poc_runner import (
    PoCAdapterUnavailable, PoCScopeRejected, SafePoCRunner,
)
from conftest import make_apk


def _runner_script(mapping):
    """Fake adb: map argv-suffix tuples to (rc, stdout, stderr)."""
    def run(argv, timeout):
        for suffix, response in mapping.items():
            if tuple(argv[-len(suffix):]) == suffix:
                return response
        return (1, b"", b"unknown command")
    return run


EMULATOR_OK = ("shell", "getprop", "ro.kernel.qemu")


def _adapter(mapping, *, emulator=True):
    responses = dict(mapping)
    responses.setdefault(EMULATOR_OK, (0, b"1\n" if emulator else b"\n", b""))
    return PhantomEmulatorAdapter(adb_path="/fake/adb", runner=_runner_script(responses))


def test_physical_device_is_refused_before_any_probe():
    adapter = _adapter({}, emulator=False)
    with pytest.raises(PoCAdapterUnavailable, match="emulator only"):
        adapter.probe_package_present("com.example")


def test_package_present_parsing():
    adapter = _adapter({
        ("shell", "pm", "list", "packages", "com.example.lab"):
            (0, b"package:com.example.lab\npackage:com.other\n", b""),
    })
    assert adapter.probe_package_present("com.example.lab").actual is True
    adapter_missing = _adapter({
        ("shell", "pm", "list", "packages", "com.example.lab"): (0, b"", b""),
    })
    assert adapter_missing.probe_package_present("com.example.lab").actual is False


def test_provider_query_row_count_and_refusal():
    adapter = _adapter({
        ("shell", "content", "query", "--uri", "content://com.example.lab.data/note"):
            (0, b"Row: 0 id=1\nRow: 1 id=2\nRow: 2 id=3\nRow: 3 id=4\n", b""),
    })
    assert adapter.probe_provider_query_rows("com.example.lab.data", "note").actual == 4
    refused = _adapter({
        ("shell", "content", "query", "--uri", "content://com.example.lab.files/x"):
            (1, b"", b"java.lang.SecurityException: Permission Denial"),
    })
    assert refused.probe_provider_query_rows("com.example.lab.files", "x").actual is None


def _context(session, store, future_iso):
    intake = IntakeService(session, store)
    app, _ = intake.create_application(make_apk(), "poc-lab.apk", uploaded_by="analyst-1")
    auth = intake.create_authorization(
        apk_sha256=app.sha256, target_package=app.package_name or "com.example",
        scope_text="Static analysis and bounded emulator probes on the lab fixture.",
        statement="I own this fixture and authorize bounded testing.",
        max_intensity=0, granted_by="analyst-1", expires_at=future_iso,
    )
    scan = intake.create_investigation(
        application_id=app.id, authorization_id=auth.id,
        objective="Exercise emulator probes", intensity=0, created_by="analyst-1",
    )
    hyp = HypothesisRow(
        id=new_id(IdPrefix.HYPOTHESIS), investigation_id=scan.id,
        claim="Exported provider rows are readable at runtime without a permission.",
        maswe=[], derived_from=[], required_evidence=["runtime_rows"],
        satisfied_evidence=[], status="open", priority=0.8, depth=0,
        parent_id=None, created_at="2026-11-18T00:00:00Z",
    )
    session.add(hyp)
    session.flush()
    return app, auth, scan, hyp


def _emulator_plan(app, auth, scan, hyp, steps):
    return PoCTestPlan(
        investigation_id=scan.id, authorization_id=auth.id,
        target_sha256=app.sha256, target_package=app.package_name or "com.example",
        target_kind="emulator", hypothesis_ids=(hyp.id,),
        steps=tuple(steps), expected_outcome="Runtime read-only probes confirm the fixture surface.",
        safety_class="read_only", max_duration_seconds=120, max_output_bytes=8192,
    )


def test_emulator_plan_fails_closed_without_adapter(session, store, future_iso):
    app, auth, scan, hyp = _context(session, store, future_iso)
    steps = (PoCStep(action="assert_emulator_package_present",
                     target_ref="com.example", expected_value=True),)
    with pytest.raises(PoCAdapterUnavailable, match="no verified Android emulator adapter"):
        SafePoCRunner(session).run(_emulator_plan(app, auth, scan, hyp, steps))


def test_emulator_plan_runs_read_only_probes(session, store, future_iso):
    app, auth, scan, hyp = _context(session, store, future_iso)
    package = app.package_name or "com.example"
    adapter = _adapter({
        ("shell", "pm", "list", "packages", package):
            (0, f"package:{package}\n".encode(), b""),
        ("shell", "content", "query", "--uri", f"content://{package}.data/note"):
            (0, b"Row: 0 id=1\nRow: 1 id=2\nRow: 2 id=3\nRow: 3 id=4\n", b""),
    })
    steps = (
        PoCStep(action="assert_emulator_package_present", target_ref=package, expected_value=True),
        PoCStep(action="assert_emulator_provider_rows",
                target_ref=f"{package}.data/note", expected_value=4),
    )
    result = SafePoCRunner(session, emulator_adapter=adapter).run(
        _emulator_plan(app, auth, scan, hyp, steps))
    assert result.status == "passed"
    assert [s.passed for s in result.steps] == [True, True]
    assert result.steps[1].actual_value == 4
    assert result.output_json["simulation_only"] is False
    assert any("verified emulator" in item for item in result.limitations)
    assert not any("not execution of the APK" in item for item in result.limitations)


def test_emulator_probe_threshold_and_refusal(session, store, future_iso):
    app, auth, scan, hyp = _context(session, store, future_iso)
    package = app.package_name or "com.example"
    adapter = _adapter({
        ("shell", "content", "query", "--uri", f"content://{package}.data/note"):
            (1, b"", b"java.lang.SecurityException: Permission Denial"),
    })
    steps = (PoCStep(action="assert_emulator_provider_rows",
                     target_ref=f"{package}.data/note", expected_value=1),)
    result = SafePoCRunner(session, emulator_adapter=adapter).run(
        _emulator_plan(app, auth, scan, hyp, steps))
    # A refused query never satisfies a readability claim.
    assert result.status == "failed"
    assert result.steps[0].passed is False


def test_emulator_probe_authority_must_stay_in_authorized_package(session, store, future_iso):
    app, auth, scan, hyp = _context(session, store, future_iso)
    adapter = _adapter({})
    steps = (PoCStep(action="assert_emulator_provider_rows",
                     target_ref="com.other.provider/x", expected_value=1),)
    with pytest.raises(PoCScopeRejected, match="authorized package"):
        SafePoCRunner(session, emulator_adapter=adapter).run(
            _emulator_plan(app, auth, scan, hyp, steps))


def test_emulator_actions_rejected_for_non_emulator_targets():
    with pytest.raises(ValueError, match="emulator target"):
        PoCTestPlan(
            investigation_id="scn_x", authorization_id="ath_x",
            target_sha256="0" * 64, target_package="com.example",
            target_kind="lab_apk", hypothesis_ids=("hyp_01M7XK6E5H4QQJ157D5W39NNBS",),
            steps=(PoCStep(action="assert_emulator_package_present",
                           target_ref="com.example", expected_value=True),),
            expected_outcome="x",
        )


def test_emulator_step_expected_value_types_enforced():
    with pytest.raises(ValueError, match="boolean"):
        PoCStep(action="assert_emulator_package_present", target_ref="com.example",
                expected_value="yes")
    with pytest.raises(ValueError, match="non-negative integer"):
        PoCStep(action="assert_emulator_provider_rows", target_ref="a.b/x",
                expected_value=True)
