"""PHANTOM emulator adapter (D-060 first slice): read-only adb probes.

The adapter's command runner and emulator check are injected, so these tests
never touch a real device. Fail-closed behavior without an adapter is pinned.
"""
from __future__ import annotations

import pytest

import hashlib
import json

from mobius.adapters.models import ApprovalRow, AuthorizationRow, HypothesisRow
from mobius.core.ids import IdPrefix, new_id
from mobius.core.schemas import PoCCleanupStep, PoCStep, PoCTestPlan
from mobius.services.intake import IntakeService
from mobius.services.phantom import _FRIDA_ENUMERATE_SCRIPT, PhantomEmulatorAdapter
from mobius.services.poc_runner import (
    PoCAdapterUnavailable, PoCApprovalRequired, PoCScopeRejected, SafePoCRunner,
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


def _adapter(mapping, *, emulator=True, frida=None):
    responses = dict(mapping)
    responses.setdefault(EMULATOR_OK, (0, b"1\n" if emulator else b"\n", b""))
    return PhantomEmulatorAdapter(
        adb_path="/fake/adb", frida_path=frida, runner=_runner_script(responses))


PIDOF_OK = ("shell", "pidof", "com.example")


def _frida_adapter(class_count=1420, rc=0):
    return _adapter(
        {PIDOF_OK: (0, b"1234\n", b""),
         ("-q", "-p", "1234", "-e", _FRIDA_ENUMERATE_SCRIPT):
            (rc, f"MOBIUS_CLASSES:{class_count}\n".encode(), b"")},
        frida="/fake/frida",
    )


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


def test_frida_enumerate_parsing_and_failures():
    adapter = _frida_adapter(1420)
    assert adapter.probe_frida_enumerate_classes("com.example").actual == 1420
    failed = _frida_adapter(rc=3)
    assert failed.probe_frida_enumerate_classes("com.example").actual is None
    no_frida = _adapter({})
    with pytest.raises(PoCAdapterUnavailable, match="frida tooling"):
        no_frida.probe_frida_enumerate_classes("com.example")


def test_frida_failure_detail_uses_fixed_classes_never_target_strings():
    # Output deliberately stuffed with target-derived strings: the persisted
    # detail must carry only the fixed class label.
    leaky = _adapter(
        {PIDOF_OK: (0, b"1234\n", b""),
         ("-q", "-p", "1234", "-e", _FRIDA_ENUMERATE_SCRIPT):
            (1, b"", b"Failed to attach: unable to find process with name "
                      b"com.example and path /data/app/com.example.private/libsecret.so")},
        frida="/fake/frida",
    )
    result = leaky.probe_frida_enumerate_classes("com.example")
    assert result.actual is None
    assert "frida-process-not-found" in result.detail
    assert "libsecret" not in result.detail
    assert "/data/app" not in result.detail
    assert "com.example" not in result.detail.split("frida-process-not-found")[-1]
    unknown = _adapter(
        {PIDOF_OK: (0, b"1234\n", b""),
         ("-q", "-p", "1234", "-e", _FRIDA_ENUMERATE_SCRIPT):
            (7, b"weird tool-specific text", b"")},
        frida="/fake/frida",
    )
    assert "frida-error-unclassified" in unknown.probe_frida_enumerate_classes("com.example").detail


def test_frida_probe_launches_app_when_process_is_gone(monkeypatch):
    # Emulator killed the app between install and execution: the probe
    # relaunches it (target-side setup) before attaching.
    calls = []

    def sequenced(argv, timeout):
        calls.append(tuple(argv))
        suffix = tuple(argv[-3:])
        if suffix == ("shell", "pidof", "com.example"):
            pidof_calls = [c for c in calls if tuple(c[-3:]) == suffix]
            if len(pidof_calls) >= 2:
                return (0, b"4321\n", b"")
            return (1, b"", b"")
        if "ro.kernel.qemu" in argv:
            return (0, b"1\n", b"")
        if "monkey" in argv:
            return (0, b"Events injected: 1\n", b"")
        if tuple(argv[-2:]) == ("-e", _FRIDA_ENUMERATE_SCRIPT):
            return (0, b"MOBIUS_CLASSES:900\n", b"")
        return (1, b"", b"unexpected")

    monkeypatch.setattr("mobius.services.phantom.time.sleep", lambda _s: None)
    adapter = PhantomEmulatorAdapter(
        adb_path="/fake/adb", frida_path="/fake/frida", runner=sequenced)
    result = adapter.probe_frida_enumerate_classes("com.example")
    assert result.actual == 900
    assert any("monkey" in c for c in calls)
    # Attach by the observed pid, not the package name (process names are
    # app labels, so name matching can miss a running process).
    attach = [c for c in calls if "-e" in c]
    assert attach and "-p" in attach[0] and "4321" in attach[0]


def test_frida_probe_fails_closed_on_ambiguous_pids():
    calls = []

    def runner(argv, timeout):
        calls.append(tuple(argv))
        suffix = tuple(argv[-3:])
        if suffix == ("shell", "pidof", "com.example"):
            return (0, b"1234 5678\n", b"")
        if "ro.kernel.qemu" in argv:
            return (0, b"1\n", b"")
        return (0, b"MOBIUS_CLASSES:9\n", b"")

    adapter = PhantomEmulatorAdapter(
        adb_path="/fake/adb", frida_path="/fake/frida", runner=runner)
    result = adapter.probe_frida_enumerate_classes("com.example")
    assert result.actual is None
    assert "frida-ambiguous-process" in result.detail
    assert not any("-e" in c for c in calls), "must not attach on ambiguity"


def test_frida_probe_fails_closed_when_process_stays_gone(monkeypatch):
    calls = []

    def runner(argv, timeout):
        calls.append(tuple(argv))
        suffix = tuple(argv[-3:])
        if suffix == ("shell", "pidof", "com.example"):
            return (1, b"", b"")
        if "ro.kernel.qemu" in argv:
            return (0, b"1\n", b"")
        if "monkey" in argv:
            return (0, b"Events injected: 1\n", b"")
        return (0, b"MOBIUS_CLASSES:9\n", b"")

    monkeypatch.setattr("mobius.services.phantom.time.sleep", lambda _s: None)
    adapter = PhantomEmulatorAdapter(
        adb_path="/fake/adb", frida_path="/fake/frida", runner=runner)
    result = adapter.probe_frida_enumerate_classes("com.example")
    assert result.actual is None
    assert "frida-process-not-running" in result.detail
    assert not any("-e" in c for c in calls), "must not attach without a pid"


def test_stop_instrumentation_is_idempotent_cleanup():
    adapter = _adapter({
        ("shell", "pkill", "-f", "frida-server"): (0, b"", b""),
    })
    assert "stopped" in adapter.stop_instrumentation()
    absent = _adapter({
        ("shell", "pkill", "-f", "frida-server"): (1, b"", b""),
    })
    assert "no running frida-server" in absent.stop_instrumentation()


def _granted_approval(session, plan):
    plan_sha = hashlib.sha256(json.dumps(
        plan.model_dump(mode="json", exclude={"approval_id"}),
        sort_keys=True, separators=(",", ":"),
    ).encode()).hexdigest()
    row = ApprovalRow(
        id=new_id(IdPrefix.APPROVAL), investigation_id=plan.investigation_id,
        requested_action="poc.execute", plan_sha256=plan_sha,
        intensity_required=1, intensity_granted=1,
        justification="unit fixture", risk_summary="unit fixture",
        state="granted", requested_by="analyst-1", decided_by="analyst-1",
        decided_at="2026-11-18T00:00:00Z", decision_note="granted",
        expires_at="2999-01-01T00:00:00Z", created_at="2026-11-18T00:00:00Z",
    )
    session.add(row)
    session.flush()
    return row


def _frida_plan(app, auth, scan, hyp, steps, approval_id=None):
    return PoCTestPlan(
        investigation_id=scan.id, authorization_id=auth.id,
        target_sha256=app.sha256, target_package=app.package_name or "com.example",
        target_kind="emulator", hypothesis_ids=(hyp.id,),
        steps=tuple(steps),
        expected_outcome="Observation-only instrumentation enumerates the lab app.",
        safety_class="non_destructive", requires_approval=True, approval_id=approval_id,
        cleanup_steps=(PoCCleanupStep(
            action="stop_emulator_instrumentation", target_ref="frida-server"),),
        max_duration_seconds=120, max_output_bytes=8192,
    )


def test_frida_plan_runs_under_granted_approval_with_cleanup(session, store, future_iso):
    app, auth, scan, hyp = _context(session, store, future_iso)
    package = app.package_name or "com.example"
    steps = (PoCStep(action="assert_emulator_frida_classes",
                     target_ref=package, expected_value=100),)
    plan = _frida_plan(app, auth, scan, hyp, steps)
    approval = _granted_approval(session, plan)
    # Same plan, same id: approval_id is excluded from the approval hash.
    plan = plan.model_copy(update={"approval_id": approval.id})
    adapter = _frida_adapter(1420)
    result = SafePoCRunner(session, emulator_adapter=adapter).run(plan)
    assert result.status == "passed"
    assert result.steps[0].actual_value == 1420
    assert "phantom-frida/" in result.tool_versions[0]
    assert result.cleanup_results[0]["status"] == "completed"
    assert any("Observation-only Frida" in item for item in result.limitations)


def test_frida_plan_requires_granted_approval(session, store, future_iso):
    app, auth, scan, hyp = _context(session, store, future_iso)
    package = app.package_name or "com.example"
    steps = (PoCStep(action="assert_emulator_frida_classes",
                     target_ref=package, expected_value=100),)
    plan = _frida_plan(app, auth, scan, hyp, steps)
    with pytest.raises(PoCApprovalRequired):
        SafePoCRunner(session, emulator_adapter=_frida_adapter()).run(plan)


def test_frida_action_requires_non_destructive_class():
    with pytest.raises(ValueError, match="non_destructive"):
        PoCTestPlan(
            investigation_id="scn_x", authorization_id="ath_x",
            target_sha256="0" * 64, target_package="com.example",
            target_kind="emulator", hypothesis_ids=("hyp_01M7XK6E5H4QQJ157D5W39NNBS",),
            steps=(PoCStep(action="assert_emulator_frida_classes",
                           target_ref="com.example", expected_value=100),),
            expected_outcome="x",
        )


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


def test_wait_for_boot_success():
    adapter = _adapter({
        ("wait-for-device",): (0, b"", b""),
        ("shell", "getprop", "sys.boot_completed"): (0, b"1\n", b""),
    })
    assert adapter.wait_for_boot() is True


def test_wait_for_boot_times_out_bounded(monkeypatch):
    monkeypatch.setattr("mobius.services.phantom.time.sleep", lambda _s: None)
    adapter = _adapter({
        ("wait-for-device",): (0, b"", b""),
        ("shell", "getprop", "sys.boot_completed"): (0, b"\n", b""),
    })
    assert adapter.wait_for_boot(budget_seconds=10, poll_seconds=2) is False


def test_wait_for_boot_fail_closed_when_device_never_returns():
    adapter = _adapter({
        ("wait-for-device",): (1, b"", b"error: closed"),
        ("shell", "getprop", "sys.boot_completed"): (0, b"1\n", b""),
    })
    assert adapter.wait_for_boot() is False


def _server_file(tmp_path, payload=b"fake-frida-server-bytes"):
    path = tmp_path / "mobius-frida-server"
    path.write_bytes(payload)
    import hashlib
    return str(path), hashlib.sha256(payload).hexdigest()


def test_start_instrumentation_refuses_digest_mismatch(tmp_path):
    path, _ = _server_file(tmp_path)
    calls = []

    def runner(argv, timeout):
        calls.append(tuple(argv))
        return (0, b"", b"")

    adapter = PhantomEmulatorAdapter(
        adb_path="/fake/adb", serial=None, runner=runner,
        emulator_check=lambda: True)
    with pytest.raises(PoCAdapterUnavailable, match="pinned sha256"):
        adapter.start_instrumentation(path, "0" * 64)
    assert not any(c[0:1] == ("/fake/adb",) and "push" in c for c in calls), \
        "no device traffic may happen before digest verification passes"


def test_start_instrumentation_happy_path(tmp_path, monkeypatch):
    path, digest = _server_file(tmp_path)
    monkeypatch.setattr("mobius.services.phantom.time.sleep", lambda _s: None)
    adapter = _adapter({
        ("root",): (0, b"restarting adbd as root\n", b""),
        ("wait-for-device",): (0, b"", b""),
        ("push", path, "/data/local/tmp/mobius-frida-server"): (0, b"", b""),
        ("shell", "chmod", "755", "/data/local/tmp/mobius-frida-server"):
            (0, b"", b""),
        ("shell", "nohup", "/data/local/tmp/mobius-frida-server",
         ">/dev/null", "2>&1", "&"): (0, b"", b""),
        ("shell", "pidof", "mobius-frida-server"): (0, b"4321\n", b""),
    })
    detail = adapter.start_instrumentation(path, digest)
    assert "started" in detail


def test_start_instrumentation_fail_closed_on_push_failure(tmp_path, monkeypatch):
    path, digest = _server_file(tmp_path)
    monkeypatch.setattr("mobius.services.phantom.time.sleep", lambda _s: None)
    adapter = _adapter({
        ("root",): (0, b"", b""),
        ("wait-for-device",): (0, b"", b""),
        ("push", path, "/data/local/tmp/mobius-frida-server"):
            (1, b"", b"error"),
    })
    with pytest.raises(PoCAdapterUnavailable, match="push failed"):
        adapter.start_instrumentation(path, digest)


def test_start_instrumentation_fail_closed_when_server_dies(tmp_path, monkeypatch):
    path, digest = _server_file(tmp_path)
    monkeypatch.setattr("mobius.services.phantom.time.sleep", lambda _s: None)
    adapter = _adapter({
        ("root",): (0, b"", b""),
        ("wait-for-device",): (0, b"", b""),
        ("push", path, "/data/local/tmp/mobius-frida-server"): (0, b"", b""),
        ("shell", "chmod", "755", "/data/local/tmp/mobius-frida-server"):
            (0, b"", b""),
        ("shell", "nohup", "/data/local/tmp/mobius-frida-server",
         ">/dev/null", "2>&1", "&"): (0, b"", b""),
        ("shell", "pidof", "mobius-frida-server"): (1, b"", b""),
    })
    with pytest.raises(PoCAdapterUnavailable, match="did not stay up"):
        adapter.start_instrumentation(path, digest)


@pytest.mark.parametrize('rc,out,err,expected',[
    (1,b'',b'java.lang.SecurityException: Permission Denial: opening provider com.example.private',True),
    (0,b'',b'java.lang.SecurityException: Permission Denial: opening provider com.example.private',True),
    (1,b'',b'error: device offline',None),
    (1,b'',b'java.lang.IllegalArgumentException: Unknown URI',None),
    (1,b'',b'java.lang.SecurityException: Something else',None),
    (0,b'No result found.\n',b'',None),
    (0,b'Row: 0 text=java.lang.SecurityException: Permission Denial: x',b'',None),
    (0,b'Row: 0 text=x\njava.lang.SecurityException: Permission Denial: x',b'',None),
])
def test_permission_denial_control_never_treats_unknown_error_or_row_text_as_denial(rc,out,err,expected):
    adapter=_adapter({('shell','content','query','--uri','content://com.example.private/note'):(rc,out,err)})
    assert adapter.probe_provider_permission_denied('com.example.private','note').actual is expected


def test_permission_denial_control_is_a_closed_boolean_step():
    with pytest.raises(ValueError):
        PoCStep(action='assert_emulator_provider_permission_denied',target_ref='com.example.private/note',expected_value=0)


def test_permission_denial_control_through_runner(session,store,future_iso):
    app,auth,scan,hyp=_context(session,store,future_iso)
    step=PoCStep(action='assert_emulator_provider_permission_denied',target_ref='com.example.private/note',expected_value=True)
    plan=_emulator_plan(app,auth,scan,hyp,(step,))
    for err,passed in [(b'java.lang.SecurityException: Permission Denial: com.example.private provider',True),(b'device offline',False)]:
        adapter=_adapter({('shell','content','query','--uri','content://com.example.private/note'):(1,b'',err)})
        result=SafePoCRunner(session,emulator_adapter=adapter).run(plan)
        assert result.steps[0].passed is passed


@pytest.mark.parametrize('rc,text,outcome,actual',[
    (0,b'Row: 0 id=1\n','readable_as_shell',1),
    (0,b'No result found.\n','empty_result',0),
    (0,b'','unclassified',None),
    (1,b'error: device offline','transport_error',None),
    (1,b'Could not find provider com.example.private','provider_not_found',None),
    (1,b'java.lang.SecurityException: Permission Denial: com.other.private','unclassified',None),
    (1,b'java.lang.SecurityException: Permission Denial: com.example.private.evil','unclassified',None),
    (1,b'java.lang.SecurityException: Permission Denial: com.example.private','permission_denied',None),
])
def test_provider_outcome_taxonomy(rc,text,outcome,actual):
    adapter=_adapter({('shell','content','query','--uri','content://com.example.private/note'):(rc,b'',text)})
    result=adapter.probe_provider_query_rows('com.example.private','note')
    assert result.outcome==outcome and result.actual==actual
    assert result.raw_output=='' # no provider row contents retained


def test_provider_timeout_distinct_from_permission_denial():
    import subprocess
    def runner(argv,timeout):
        if argv[-1]=='ro.kernel.qemu':return 0,b'1',b''
        raise subprocess.TimeoutExpired(argv,timeout)
    result=PhantomEmulatorAdapter(adb_path='/fake/adb',runner=runner).probe_provider_permission_denied('com.example.private','note')
    assert result.outcome=='transport_error' and result.actual is None


@pytest.mark.parametrize('case',['good','root','uid_error','split','wrong_hash','wrong_serial','bad_path'])
def test_installed_identity_is_exact_base_apk_and_nonroot_shell(case):
    import hashlib
    digest=hashlib.sha256(b'unit fixture bytes').hexdigest()
    path='/data/app/~~random/com.example-random/base.apk'
    calls=[]
    def runner(argv,timeout):
        calls.append(tuple(argv))
        if argv[-1]=='ro.kernel.qemu':return 0,b'1',b''
        if argv[-2:]==['id','-u']:
            return (1,b'',b'error') if case=='uid_error' else (0,b'0' if case=='root' else b'2000\n',b'')
        if argv[-3:]==['pm','path','com.example']:
            lines='package:'+path
            if case=='split':lines+='\npackage:/data/app/split.apk'
            if case=='bad_path':lines='package:/data/app/a/../../bad/base.apk'
            return 0,lines.encode(),b''
        if argv[-2:]==['sha256sum',path]:
            return 0,((('b'*64) if case=='wrong_hash' else digest)+'  '+path+'\n').encode(),b''
        raise AssertionError(argv)
    adapter=PhantomEmulatorAdapter(adb_path='/fake/adb',serial='emulator-5554',runner=runner)
    if case=='good':adapter.verify_installed_identity('com.example',digest,'emulator-5554',2000)
    else:
        with pytest.raises(PoCAdapterUnavailable):
            adapter.verify_installed_identity('com.example',digest,'emulator-5556' if case=='wrong_serial' else 'emulator-5554',2000)
    assert not any('query' in c for c in calls)


def test_real_subprocess_stream_bound_and_timeout(monkeypatch):
    """Local inert Python children only, not adb/emulator/runtime evidence."""
    import sys,subprocess
    import mobius.services.phantom as phantom
    monkeypatch.setattr(phantom,'MAX_OUTPUT_BYTES',1024)
    assert phantom._subprocess_runner([sys.executable,'-c','print(123)'],2)==(0,b'123\n',b'')
    for stream in ('stdout','stderr'):
        with pytest.raises(PoCAdapterUnavailable,match='output limit'):
            phantom._subprocess_runner([sys.executable,'-c',f'import sys;sys.{stream}.write("x"*1000000)'],2)
    with pytest.raises(subprocess.TimeoutExpired):
        phantom._subprocess_runner([sys.executable,'-c','import time;time.sleep(5)'],.05)


@pytest.mark.parametrize('authority,path',[('com.example;id','note'),('com.example','$(id)'),('com.example','x/y')])
def test_provider_query_rejects_remote_shell_metacharacters_before_adb(authority,path):
    def runner(*args):raise AssertionError('must reject before adb')
    with pytest.raises(PoCAdapterUnavailable,match='literal authority'):
        PhantomEmulatorAdapter(adb_path='/fake',runner=runner).probe_provider_query_rows(authority,path)
