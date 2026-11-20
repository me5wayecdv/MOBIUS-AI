"""Bounded provider-analysis worker: dispatch contract, container entrypoint,
and the payload wire format with its negative cases.

The worker parses attacker-supplied APK bytes; every test here exists so a
malformed, oversized, mis-bound, or semantically impossible worker result is
rejected BEFORE it can influence a finding.
"""
from __future__ import annotations

import hashlib
import json
import zipfile
from io import BytesIO
from pathlib import Path

import pytest

from mobius.adapters.flow_adapt import DexBlobCoverage
from mobius.adapters.provider_payload import (
    MAX_PROVIDER_JSON_BYTES,
    provider_analysis_payload,
    validate_provider_analysis_payload,
)
from mobius.core.providers import (
    GuardFinding,
    OperationExposure,
    ProviderExposure,
    SinkFlowEvidence,
)
from mobius.worker.runner import _PROVIDER_BINARY, _tool_for

IMAGE = "ghcr.io/me5wayecdv/mobius-provider@sha256:" + "c" * 64
FIXTURE_DEX = Path(__file__).parent / "fixtures" / "dex" / "AnalysisTest.dex"

_PROVIDER_MANIFEST = (
    '<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.example">'
    "<application>"
    "<provider android:name='.NotesProvider' android:authorities='com.example.notes' "
    "android:exported='true'/>"
    "</application></manifest>"
)


def _fixture_apk() -> bytes:
    stream = BytesIO()
    with zipfile.ZipFile(stream, "w") as archive:
        archive.writestr("AndroidManifest.xml", _PROVIDER_MANIFEST)
        archive.writestr("classes.dex", FIXTURE_DEX.read_bytes())
    return stream.getvalue()


def _sample_exposure(**overrides) -> ProviderExposure:
    op = OperationExposure(
        operation="read",
        protection_status="unprotected",
        protection_permission=None,
        protection_basis="no provider permission declared",
        caller_check_absent=True,
        guard_findings=(
            GuardFinding("Landroid/content/Context;->checkCallingPermission", "ignored",
                         "result unused"),
        ),
        coverage_complete=True,
        sink_flows=(
            SinkFlowEvidence("com.example.NotesProvider.query", "SQLiteDatabase.rawQuery",
                             "caller-controlled projection"),
        ),
        flow_complete=True,
    )
    op = overrides.pop("operation_override", op)
    return ProviderExposure(
        provider=overrides.pop("provider", "com.example.NotesProvider"),
        exported=True,
        grant_uri_permissions=False,
        uri_patterns=(),
        numeric_uri_patterns=(),
        operations=(op,),
        **overrides,
    )


def _sample_payload(sha: str) -> dict:
    return provider_analysis_payload(
        artifact_sha256=sha,
        package_name="com.example",
        methods_adapted=3,
        ledger=[DexBlobCoverage("classes.dex", "parsed", 100, methods=3)],
        exposures=[_sample_exposure()],
    )


# ---------------------------------------------------------------------------
# dispatch contract
# ---------------------------------------------------------------------------

def test_provider_job_uses_only_the_registered_image_and_networkless_limits(monkeypatch):
    monkeypatch.setenv("MOBIUS_PROVIDER_IMAGE", IMAGE)
    binary, image, spec = _tool_for("provider_analysis", "/usr/bin/podman")

    assert binary == _PROVIDER_BINARY
    assert image == IMAGE
    assert spec.name == "provider_analysis"
    assert spec.limits.network_enabled is False
    assert spec.limits.memory_mb == 4096
    assert spec.limits.timeout_seconds == 900
    assert spec.argv_for({}) == (_PROVIDER_BINARY, "--input", "/work/input.apk")


def test_provider_dispatch_requires_an_immutable_image_reference(monkeypatch):
    monkeypatch.setenv("MOBIUS_PROVIDER_IMAGE", "ghcr.io/example/mobius-provider:latest")
    with pytest.raises(ValueError, match="immutable sha256"):
        _tool_for("provider_analysis", "/usr/bin/podman")


# ---------------------------------------------------------------------------
# container entrypoint
# ---------------------------------------------------------------------------

def test_entrypoint_refuses_any_input_but_the_staged_file(tmp_path, capsys):
    from mobius.worker.provider_analysis import main

    assert main.__wrapped__ if hasattr(main, "__wrapped__") else True
    import sys
    argv = sys.argv
    try:
        sys.argv = ["mobius-provider-analysis", "--input", str(tmp_path / "evil.apk")]
        assert main() == 2
    finally:
        sys.argv = argv
    assert "staged" in capsys.readouterr().err


def test_entrypoint_analyses_a_real_provider_apk(tmp_path, monkeypatch, capsys):
    from mobius.worker import provider_analysis as entry

    staged = tmp_path / "input.apk"
    apk = _fixture_apk()
    staged.write_bytes(apk)
    monkeypatch.setattr(entry, "_STAGED_INPUT", staged)

    import sys
    argv = sys.argv
    try:
        sys.argv = ["mobius-provider-analysis", "--input", str(staged)]
        assert entry.main() == 0
    finally:
        sys.argv = argv

    raw = capsys.readouterr().out.encode()
    result = validate_provider_analysis_payload(raw, hashlib.sha256(apk).hexdigest())
    assert result.package_name == "com.example"
    assert result.dex_complete is True
    assert any(e.provider.endswith("NotesProvider") for e in result.exposures)


def test_entrypoint_output_budget_is_enforced(tmp_path, monkeypatch, capsys):
    from mobius.worker import provider_analysis as entry

    staged = tmp_path / "input.apk"
    staged.write_bytes(_fixture_apk())
    monkeypatch.setattr(entry, "_STAGED_INPUT", staged)
    monkeypatch.setattr(entry, "MAX_PROVIDER_JSON_BYTES", 16)

    import sys
    argv = sys.argv
    try:
        sys.argv = ["mobius-provider-analysis", "--input", str(staged)]
        assert entry.main() == 4
    finally:
        sys.argv = argv
    assert "budget" in capsys.readouterr().err


def test_entrypoint_broken_apk_is_a_failure_class_not_a_result(tmp_path, monkeypatch, capsys):
    from mobius.worker import provider_analysis as entry

    staged = tmp_path / "input.apk"
    staged.write_bytes(b"not a zip at all")
    monkeypatch.setattr(entry, "_STAGED_INPUT", staged)

    import sys
    argv = sys.argv
    try:
        sys.argv = ["mobius-provider-analysis", "--input", str(staged)]
        assert entry.main() == 3
    finally:
        sys.argv = argv
    assert capsys.readouterr().out == ""


# ---------------------------------------------------------------------------
# payload wire format: round-trip and negatives
# ---------------------------------------------------------------------------

def test_payload_round_trip_preserves_evidence():
    sha = "a" * 64
    raw = json.dumps(_sample_payload(sha)).encode()
    result = validate_provider_analysis_payload(raw, sha)

    assert result.package_name == "com.example"
    assert result.methods_adapted == 3
    assert result.dex_complete is True
    exposure = result.exposures[0]
    assert exposure.provider == "com.example.NotesProvider"
    op = exposure.operations[0]
    assert op.caller_check_absent is True
    assert op.guard_findings[0].outcome == "ignored"
    assert op.sink_flows[0].sink == "SQLiteDatabase.rawQuery"


def test_payload_rejects_different_artifact_digest():
    raw = json.dumps(_sample_payload("a" * 64)).encode()
    with pytest.raises(ValueError, match="not bound to the authorized APK"):
        validate_provider_analysis_payload(raw, "b" * 64)


def test_payload_rejects_oversized_output():
    with pytest.raises(ValueError, match="size limit"):
        validate_provider_analysis_payload(b" " * (MAX_PROVIDER_JSON_BYTES + 1), "a" * 64)


def test_payload_rejects_unknown_schema_version():
    payload = _sample_payload("a" * 64)
    payload["schema_version"] = 2
    with pytest.raises(ValueError, match="invalid schema"):
        validate_provider_analysis_payload(json.dumps(payload).encode(), "a" * 64)


def test_payload_rejects_extra_fields():
    payload = _sample_payload("a" * 64)
    payload["verdict"] = "confirmed"  # a worker must never smuggle decisions
    with pytest.raises(ValueError, match="invalid schema"):
        validate_provider_analysis_payload(json.dumps(payload).encode(), "a" * 64)


def test_payload_rejects_unknown_guard_outcome():
    payload = _sample_payload("a" * 64)
    payload["exposures"][0]["operations"][0]["guard_findings"][0]["outcome"] = "enforcing-ish"
    with pytest.raises(ValueError, match="unknown guard outcome"):
        validate_provider_analysis_payload(json.dumps(payload).encode(), "a" * 64)


def test_payload_rejects_unknown_protection_status():
    payload = _sample_payload("a" * 64)
    payload["exposures"][0]["operations"][0]["protection_status"] = "probably-fine"
    with pytest.raises(ValueError, match="unknown protection status"):
        validate_provider_analysis_payload(json.dumps(payload).encode(), "a" * 64)


def test_payload_rejects_unprotected_operation_carrying_a_permission():
    payload = _sample_payload("a" * 64)
    payload["exposures"][0]["operations"][0]["protection_permission"] = "android.permission.X"
    with pytest.raises(ValueError, match="unprotected operation carries a permission"):
        validate_provider_analysis_payload(json.dumps(payload).encode(), "a" * 64)


def test_payload_rejects_duplicate_operations_and_ledger_entries():
    payload = _sample_payload("a" * 64)
    ops = payload["exposures"][0]["operations"]
    ops.append(dict(ops[0]))
    with pytest.raises(ValueError, match="duplicate provider operation"):
        validate_provider_analysis_payload(json.dumps(payload).encode(), "a" * 64)

    payload = _sample_payload("a" * 64)
    payload["dex_coverage"].append(dict(payload["dex_coverage"][0]))
    with pytest.raises(ValueError, match="duplicate DEX coverage entry"):
        validate_provider_analysis_payload(json.dumps(payload).encode(), "a" * 64)


def test_payload_rejects_methods_count_contradicting_the_ledger():
    payload = _sample_payload("a" * 64)
    payload["methods_adapted"] = 99
    with pytest.raises(ValueError, match="contradicts the DEX ledger"):
        validate_provider_analysis_payload(json.dumps(payload).encode(), "a" * 64)


def test_dex_completeness_is_recomputed_from_the_ledger_not_the_worker():
    """A partial DEX ledger must downgrade to incomplete API-side, even though
    the worker never claims completeness in the payload at all."""
    sha = "a" * 64
    payload = provider_analysis_payload(
        artifact_sha256=sha,
        package_name="com.example",
        methods_adapted=3,
        ledger=[
            DexBlobCoverage("classes.dex", "parsed", 100, methods=3),
            DexBlobCoverage("classes2.dex", "failed-parse", 50, error="BadDEX"),
        ],
        exposures=[_sample_exposure()],
    )
    result = validate_provider_analysis_payload(json.dumps(payload).encode(), sha)
    assert result.dex_complete is False


def _multi_dex_apk(names) -> bytes:
    stream = BytesIO()
    with zipfile.ZipFile(stream, "w") as archive:
        archive.writestr("AndroidManifest.xml", _PROVIDER_MANIFEST)
        for name in names:
            archive.writestr(name, FIXTURE_DEX.read_bytes())
    return stream.getvalue()


def test_dex_entries_use_numeric_runtime_order():
    """classes2.dex must be analysed before classes10.dex; lexicographic
    ordering would invert them."""
    from mobius.adapters.flow_adapt import dex_entries
    apk = _multi_dex_apk(("classes10.dex", "classes.dex", "classes2.dex"))
    names = [name for name, _size, _raw, _skip in dex_entries(apk)]
    assert names == ["classes.dex", "classes2.dex", "classes10.dex"]


def test_duplicate_class_first_dex_wins_and_is_counted():
    """The same method in two dex files: the runtime resolves the FIRST dex
    (DexPathList front-to-back, AOSP dx KEEP_FIRST). The adapter must keep the
    first body, skip the copy, and account for it in the ledger."""
    from mobius.adapters.flow_adapt import adapt_code
    apk = _multi_dex_apk(("classes.dex", "classes2.dex"))
    methods, _rs, _sc, _tr, ledger = adapt_code(apk)
    parsed = [row for row in ledger if row.status == "parsed"]
    assert len(parsed) == 2
    assert parsed[0].methods == len(methods) and parsed[0].duplicates == 0
    assert parsed[1].methods == 0
    assert parsed[1].duplicates == parsed[0].methods
    # ANY duplicate class marks ambiguity, identical content included:
    # first-wins is a classpath-order assumption, not runtime verification
    assert parsed[1].ambiguous is True


def test_duplicate_zip_entry_name_is_visible_not_reread():
    from mobius.adapters.flow_adapt import dex_entries
    apk = _multi_dex_apk(("classes.dex", "classes.dex"))
    rows = dex_entries(apk)
    assert rows[0][2] is not None
    assert rows[1][2] is None and rows[1][3] == "duplicate zip entry name"


def _payload(**overrides) -> dict:
    import hashlib
    base = {
        "schema_version": 1,
        "artifact_sha256": hashlib.sha256(b"apk").hexdigest(),
        "package_name": "com.example",
        "methods_adapted": 1,
        "dex_coverage": [{"entry": "classes.dex", "status": "parsed",
                          "size_bytes": 100, "methods": 1}],
        "exposures": [],
    }
    base.update(overrides)
    return base


def _operation_payload(**overrides) -> dict:
    op = {
        "operation": "read",
        "protection_status": "unprotected",
        "protection_permission": None,
        "protection_basis": "none declared",
        "caller_check_absent": True,
        "guard_findings": [],
        "coverage_complete": True,
        "sink_flows": [{"method": "m", "sink": "s", "detail": "d"}],
        "flow_complete": True,
    }
    op.update(overrides)
    return op


def test_payload_rejects_protected_without_permission():
    from mobius.adapters.provider_payload import validate_provider_analysis_payload
    import hashlib, json
    op = _operation_payload(protection_status="protected", protection_permission=None)
    payload = _payload(exposures=[{
        "provider": "com.example.P", "exported": True, "operations": [op]}])
    with pytest.raises(ValueError, match="protected operation without a permission"):
        validate_provider_analysis_payload(
            json.dumps(payload).encode(), hashlib.sha256(b"apk").hexdigest())


def test_payload_rejects_absent_with_incomplete_flow():
    from mobius.adapters.provider_payload import validate_provider_analysis_payload
    import hashlib, json
    op = _operation_payload(flow_complete=False)
    payload = _payload(exposures=[{
        "provider": "com.example.P", "exported": True, "operations": [op]}])
    with pytest.raises(ValueError, match="incomplete coverage/flow"):
        validate_provider_analysis_payload(
            json.dumps(payload).encode(), hashlib.sha256(b"apk").hexdigest())


def test_payload_rejects_absent_contradicted_by_enforcing_guard():
    from mobius.adapters.provider_payload import validate_provider_analysis_payload
    import hashlib, json
    op = _operation_payload(guard_findings=[{
        "api": "Landroid/content/Context;->checkCallingPermission",
        "outcome": "enforcing", "detail": "gates sink"}])
    payload = _payload(exposures=[{
        "provider": "com.example.P", "exported": True, "operations": [op]}])
    with pytest.raises(ValueError, match="contradicted by an enforcing guard"):
        validate_provider_analysis_payload(
            json.dumps(payload).encode(), hashlib.sha256(b"apk").hexdigest())


def test_payload_rejects_duplicate_providers():
    from mobius.adapters.provider_payload import validate_provider_analysis_payload
    import hashlib, json
    op = _operation_payload(caller_check_absent=False)
    payload = _payload(exposures=[
        {"provider": "com.example.P", "exported": True, "operations": [op]},
        {"provider": "com.example.P", "exported": True, "operations": [op]},
    ])
    with pytest.raises(ValueError, match="duplicate provider entry"):
        validate_provider_analysis_payload(
            json.dumps(payload).encode(), hashlib.sha256(b"apk").hexdigest())


def test_payload_accepts_legitimate_duplicate_entry_ledger_rows():
    from mobius.adapters.provider_payload import validate_provider_analysis_payload
    import hashlib, json
    payload = _payload(dex_coverage=[
        {"entry": "classes.dex", "status": "parsed", "size_bytes": 100, "methods": 1},
        {"entry": "classes.dex", "status": "duplicate-entry", "size_bytes": 100},
    ])
    result = validate_provider_analysis_payload(
        json.dumps(payload).encode(), hashlib.sha256(b"apk").hexdigest())
    assert len(result.ledger) == 2


def test_duplicate_class_with_disjoint_methods_is_skipped_and_marks_ambiguity(monkeypatch):
    """Same class name in two dex files with DIFFERENT method sets: the whole
    second class is skipped (runtime first-wins resolves the class, not the
    methods), the disjoint copy marks the entry ambiguous, and the ambiguity
    downgrades coverage instead of being silently merged."""
    import mobius.adapters.flow_adapt as fa

    class _Code:
        tries = ()
        def get_registers_size(self):
            return 4

    class _M:
        def __init__(self, name, desc):
            self._n, self._d = name, desc
        def get_name(self):
            return self._n
        def get_descriptor(self):
            return self._d
        def get_code(self):
            return _Code()

    class _C:
        def __init__(self, methods):
            self._m = methods
        def get_name(self):
            return "Lcom/example/Dup;"
        def get_superclassname(self):
            return "Ljava/lang/Object;"
        def get_methods(self):
            return self._m

    class _FakeDEX:
        calls = 0
        def __init__(self, raw):
            _FakeDEX.calls += 1
            if _FakeDEX.calls == 1:
                self._classes = [_C([_M("a", "()V"), _M("b", "()V")])]
            else:
                # same class, disjoint/divergent method set
                self._classes = [_C([_M("a", "()V"), _M("c", "()V")])]
        def get_classes(self):
            return self._classes

    import androguard.core.dex as agdex
    monkeypatch.setattr(agdex, "DEX", _FakeDEX)
    monkeypatch.setattr(fa, "flow_scan_from_androguard", lambda vm, em: None)

    apk = _multi_dex_apk(("classes.dex", "classes2.dex"))
    methods, _rs, _sc, _tr, ledger = fa.adapt_code(apk)
    assert _FakeDEX.calls == 2
    parsed = [row for row in ledger if row.status == "parsed"]
    assert len(parsed) == 2
    assert parsed[0].duplicates == 0 and not parsed[0].ambiguous
    # whole second class skipped: 2 methods counted as duplicates, none adapted
    assert parsed[1].methods == 0 and parsed[1].duplicates == 2
    assert parsed[1].ambiguous is True
    assert not methods  # flow_scan returned None; nothing adapted (accounting only)


def test_payload_ambiguous_ledger_entry_downgrades_dex_complete():
    from mobius.adapters.provider_payload import validate_provider_analysis_payload
    import hashlib, json
    payload = _payload(dex_coverage=[
        {"entry": "classes.dex", "status": "parsed", "size_bytes": 100, "methods": 1},
        {"entry": "classes2.dex", "status": "parsed", "size_bytes": 100,
         "methods": 0, "duplicates": 2, "ambiguous": True},
    ])
    result = validate_provider_analysis_payload(
        json.dumps(payload).encode(), hashlib.sha256(b"apk").hexdigest())
    assert result.dex_complete is False  # ambiguity downgrades coverage


def test_service_and_dto_share_one_coverage_predicate():
    """Closure item: the in-process service path and the API result DTO must
    compute dex completeness with the SAME predicate (shared helper) - an
    ambiguous duplicate entry downgrades coverage exactly like a failed parse,
    in both directions."""
    from mobius.adapters.flow_adapt import DexBlobCoverage
    from mobius.adapters.provider_payload import (
        ProviderAnalysisResult, dex_ledger_complete)

    def ledger(*specs):
        return tuple(DexBlobCoverage(entry=e, status=s, size_bytes=1, ambiguous=a)
                     for e, s, a in specs)

    cases = (
        (True, ledger(("classes.dex", "parsed", False))),
        (False, ledger(("classes.dex", "failed-parse", False))),
        (False, ledger(("classes.dex", "parsed", True))),  # ambiguous duplicate
        (False, ledger(("classes.dex", "parsed", False),
                       ("classes2.dex", "parsed", True))),
        (False, ledger()),
    )
    for expected, cov in cases:
        result = ProviderAnalysisResult(
            package_name="p", methods_adapted=0, ledger=cov, exposures=())
        assert result.dex_complete is expected
        assert dex_ledger_complete(cov) is expected


# ---------------------------------------------------------------------------
# bounded app-first adaptation
# ---------------------------------------------------------------------------


class _BudgetCode:
    tries = ()

    def get_registers_size(self):
        return 2


class _BudgetMethod:
    def __init__(self, name, descriptor="()V"):
        self._name, self._descriptor = name, descriptor

    def get_name(self):
        return self._name

    def get_descriptor(self):
        return self._descriptor

    def get_code(self):
        return _BudgetCode()


class _BudgetClass:
    def __init__(self, descriptor, methods, superclass="Ljava/lang/Object;"):
        self._name, self._methods, self._super = descriptor, list(methods), superclass

    def get_name(self):
        return self._name

    def get_methods(self):
        return list(self._methods)

    def get_superclassname(self):
        return self._super


class _BudgetDex:
    def __init__(self, classes):
        self._classes = list(classes)

    def get_classes(self):
        return list(self._classes)


def _budget_apk(entries: dict[str, bytes]) -> bytes:
    stream = BytesIO()
    with zipfile.ZipFile(stream, "w") as archive:
        archive.writestr("AndroidManifest.xml", _PROVIDER_MANIFEST)
        for name, raw in entries.items():
            archive.writestr(name, raw)
    return stream.getvalue()


def _patch_budget_dex(monkeypatch, fakes: dict[bytes, object]):
    monkeypatch.setattr("androguard.core.dex.DEX", lambda raw: fakes[raw])
    monkeypatch.setattr(
        "mobius.adapters.flow_adapt.flow_scan_from_androguard",
        lambda vm, em: (id(vm), em.get_name()),
    )


def test_budget_truncates_inside_an_app_entry_and_skips_library(monkeypatch):
    from mobius.adapters.flow_adapt import adapt_code
    from mobius.adapters.provider_payload import dex_ledger_complete

    fakes = {
        b"lib": _BudgetDex([_BudgetClass("Lcom/lib/Util;", [_BudgetMethod(n) for n in ("a", "b", "c")])]),
        b"app": _BudgetDex([
            _BudgetClass("Lcom/example/app/Main;", [_BudgetMethod("onCreate"), _BudgetMethod("onStart")]),
            _BudgetClass("Lcom/example/app/Other;", [_BudgetMethod("m")]),
        ]),
    }
    _patch_budget_dex(monkeypatch, fakes)
    apk = _budget_apk({"classes.dex": b"lib", "classes2.dex": b"app"})
    methods, _r, _s, _t, ledger = adapt_code(apk, max_methods=2, app_package="com.example.app")
    # the app entry spent the whole budget and was cut mid-entry; the library
    # entry was never reached. Both downgrade coverage; neither is "parsed".
    assert len(methods) == 2
    assert {m.class_name for m in methods} == {"com.example.app.Main"}
    by_entry = {b.entry: b for b in ledger}
    assert [b.entry for b in ledger] == ["classes.dex", "classes2.dex"]  # runtime order
    assert by_entry["classes2.dex"].status == "truncated-budget"
    assert by_entry["classes2.dex"].methods == 2
    assert by_entry["classes.dex"].status == "skipped-budget"
    assert by_entry["classes.dex"].methods == 0
    assert dex_ledger_complete(ledger) is False


def test_budget_exhaustion_at_entry_boundary_skips_whole_entry(monkeypatch):
    from mobius.adapters.flow_adapt import adapt_code
    from mobius.adapters.provider_payload import dex_ledger_complete

    fakes = {
        b"lib": _BudgetDex([_BudgetClass("Lcom/lib/Util;", [_BudgetMethod("a")])]),
        b"app": _BudgetDex([
            _BudgetClass("Lcom/example/app/Main;", [_BudgetMethod("onCreate"), _BudgetMethod("onStart")]),
            _BudgetClass("Lcom/example/app/Other;", [_BudgetMethod("m")]),
        ]),
    }
    _patch_budget_dex(monkeypatch, fakes)
    apk = _budget_apk({"classes.dex": b"lib", "classes2.dex": b"app"})
    methods, _r, _s, _t, ledger = adapt_code(apk, max_methods=3, app_package="com.example.app")
    assert len(methods) == 3
    by_entry = {b.entry: b for b in ledger}
    # the app entry exactly fills the budget: fully parsed; the library entry
    # is then skipped whole, not truncated.
    assert by_entry["classes2.dex"].status == "parsed"
    assert by_entry["classes2.dex"].methods == 3
    assert by_entry["classes.dex"].status == "skipped-budget"
    assert dex_ledger_complete(ledger) is False


def test_first_wins_duplicate_resolution_follows_runtime_order_not_budget_order(monkeypatch):
    from mobius.adapters.flow_adapt import adapt_code

    lib_vm = _BudgetDex([
        _BudgetClass("Lcom/example/app/Dup;", [_BudgetMethod("m1")]),
        _BudgetClass("Lcom/lib/Util;", [_BudgetMethod("u")]),
    ])
    app_vm = _BudgetDex([
        _BudgetClass("Lcom/example/app/Dup;", [_BudgetMethod("m1")]),
        _BudgetClass("Lcom/example/app/Main;", [_BudgetMethod("onCreate")]),
    ])
    fakes = {b"lib": lib_vm, b"app": app_vm}
    _patch_budget_dex(monkeypatch, fakes)
    apk = _budget_apk({"classes.dex": b"lib", "classes2.dex": b"app"})
    methods, _r, superclasses, _t, ledger = adapt_code(apk, max_methods=10, app_package="com.example.app")
    # classes.dex claimed Dup first (runtime order), and its copy is the one
    # adapted even though the app entry was visited first under the budget order.
    dup = next(m for m in methods if m.class_name == "com.example.app.Dup")
    assert methods[dup] == (id(lib_vm), "m1")
    assert len(methods) == 3
    by_entry = {b.entry: b for b in ledger}
    assert by_entry["classes2.dex"].ambiguous is True
    assert by_entry["classes2.dex"].duplicates == 1
    assert by_entry["classes2.dex"].status == "parsed"
    # superclasses of claimed classes stay recorded for the winning copies
    assert superclasses["com.example.app.Dup"] == "java.lang.Object"


def test_no_package_means_plain_runtime_order(monkeypatch):
    from mobius.adapters.flow_adapt import adapt_code

    fakes = {
        b"lib": _BudgetDex([_BudgetClass("Lcom/lib/Util;", [_BudgetMethod(n) for n in ("a", "b", "c")])]),
        b"app": _BudgetDex([_BudgetClass("Lcom/example/app/Main;", [_BudgetMethod("onCreate")])]),
    }
    _patch_budget_dex(monkeypatch, fakes)
    apk = _budget_apk({"classes.dex": b"lib", "classes2.dex": b"app"})
    methods, _r, _s, _t, ledger = adapt_code(apk, max_methods=3)
    by_entry = {b.entry: b for b in ledger}
    # without a package, name/runtime order decides: library entry fills the
    # budget exactly (parsed), app entry skipped whole.
    assert by_entry["classes.dex"].status == "parsed"
    assert by_entry["classes.dex"].methods == 3
    assert by_entry["classes2.dex"].status == "skipped-budget"
    assert len(methods) == 3


def test_payload_accepts_budget_statuses_and_accounts_adapted_methods():
    apk = _fixture_apk()
    sha = hashlib.sha256(apk).hexdigest()
    payload = provider_analysis_payload(
        artifact_sha256=sha,
        package_name="com.example",
        methods_adapted=2,
        ledger=[
            DexBlobCoverage("classes.dex", "skipped-budget", 100, error="global method budget exhausted"),
            DexBlobCoverage("classes2.dex", "truncated-budget", 100, methods=2,
                            error="global method budget exhausted"),
        ],
        exposures=[_sample_exposure()],
    )
    result = validate_provider_analysis_payload(json.dumps(payload).encode(), sha)
    assert result.methods_adapted == 2
    assert result.dex_complete is False  # no false confirm/refute on partial coverage


def test_payload_rejects_methods_count_ignoring_truncated_entries():
    apk = _fixture_apk()
    sha = hashlib.sha256(apk).hexdigest()
    payload = provider_analysis_payload(
        artifact_sha256=sha,
        package_name="com.example",
        methods_adapted=3,
        ledger=[DexBlobCoverage("classes.dex", "truncated-budget", 100, methods=2)],
        exposures=[_sample_exposure()],
    )
    with pytest.raises(ValueError, match="contradicts the DEX ledger"):
        validate_provider_analysis_payload(json.dumps(payload).encode(), sha)


def test_entrypoint_binds_adaptation_budget_and_manifest_package(tmp_path, monkeypatch, capsys):
    from mobius.adapters.dex import MAX_METHODS
    from mobius.worker import provider_analysis as entry

    staged = tmp_path / "input.apk"
    apk = _fixture_apk()
    staged.write_bytes(apk)
    monkeypatch.setattr(entry, "_STAGED_INPUT", staged)
    captured = {}
    real_adapt = entry.adapt_code

    def spy(apk_bytes, **kwargs):
        captured.update(kwargs)
        return real_adapt(apk_bytes, **kwargs)

    monkeypatch.setattr(entry, "adapt_code", spy)

    import sys
    argv = sys.argv
    try:
        sys.argv = ["mobius-provider-analysis", "--input", str(staged)]
        assert entry.main() == 0
    finally:
        sys.argv = argv
    assert captured == {"max_methods": MAX_METHODS, "app_package": "com.example"}
