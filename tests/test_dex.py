"""Dex extraction, against a real dex file.

The fixture is a genuine dalvik dex from androguard's Apache-2.0 test corpus (see
`tests/fixtures/dex/NOTICE.md`), so this exercises androguard's parser and our translation
rather than a hand-built fake. What it does not exercise is scale or obfuscation - recorded
in RL-006 rather than implied away.
"""

from __future__ import annotations

import io
import pathlib
import zipfile

import pytest

from mobius.adapters.dex import CodeIndex, DexIndexError, index_apk, index_dex
from mobius.core.reachability import MethodRef

FIXTURE = pathlib.Path(__file__).parent / "fixtures" / "dex" / "AnalysisTest.dex"


@pytest.fixture(scope="module")
def dex_bytes() -> bytes:
    return FIXTURE.read_bytes()


@pytest.fixture(scope="module")
def index(dex_bytes) -> CodeIndex:
    return index_dex(dex_bytes)


def test_fixture_is_present_and_non_empty(dex_bytes):
    assert len(dex_bytes) > 100
    assert dex_bytes[:3] == b"dex"


def test_classes_are_discovered(index):
    assert index.classes == ("AnalysisTest",)
    assert index.methods >= 4
    assert index.truncated is False


def test_class_names_are_dotted_not_descriptors(index):
    assert all(not c.startswith("L") and not c.endswith(";") for c in index.classes)


def test_boundary_calls_are_captured(index):
    targets = {
        (call.class_descriptor, call.method)
        for calls in index.boundary.values()
        for call in calls
    }
    assert ("Ljava/math/BigInteger;", "doubleValue") in targets
    assert ("Ljava/io/PrintStream;", "println") in targets


def test_every_application_method_is_a_graph_node(index):
    """A lifecycle method that only calls framework APIs must still be findable, otherwise
    it reads as "the component has no entry point"."""
    assert index.graph.edges, "graph must contain nodes even without internal calls"
    assert all(callees == () or isinstance(callees, tuple) for callees in index.graph.edges.values())
    assert len(index.graph) == index.methods


def test_framework_calls_are_not_graph_edges(index):
    """Every edge must be between classes defined in this dex, otherwise the search could
    walk into the platform and manufacture a path."""
    internal = {m.class_name for m in index.graph.edges} | {
        c.class_name for callees in index.graph.edges.values() for c in callees
    }
    assert internal <= set(index.classes)


def test_string_constants_are_captured(index):
    literals = [s for strings in index.strings.values() for s in strings]
    assert "Hello world" in literals


def test_describe_reports_counts(index):
    described = index.describe()
    assert described["classes"] == 1
    # Four methods, none of which call another application method, so the graph has four
    # nodes and no internal edges - every call it makes leaves the application.
    assert described["graph_nodes"] == 4
    assert described["internal_calls"] == 0
    assert described["truncated"] is False


def test_apk_entry_point_matches_bare_dex(dex_bytes, index):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("classes.dex", dex_bytes)
    assert index_apk(buf.getvalue()).classes == index.classes


def test_multiple_dex_files_are_merged(dex_bytes):
    merged = index_dex(dex_bytes, dex_bytes)
    assert merged.classes == ("AnalysisTest",)
    assert merged.methods == 2 * index_dex(dex_bytes).methods


def test_method_budget_marks_the_index_truncated(dex_bytes):
    limited = index_dex(dex_bytes, max_methods=1)
    assert limited.truncated is True
    assert limited.methods == 1


def test_non_zip_is_rejected():
    with pytest.raises(DexIndexError, match="cannot read APK"):
        index_apk(b"not a zip")


def test_zip_without_dex_is_rejected():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("AndroidManifest.xml", "<manifest package='x'/>")
    with pytest.raises(DexIndexError, match="no classes"):
        index_apk(buf.getvalue())


def test_corrupt_dex_is_rejected():
    with pytest.raises(DexIndexError, match="cannot parse"):
        index_dex(b"dex\n035\x00" + b"\x00" * 60)


def test_no_input_is_rejected():
    with pytest.raises(DexIndexError):
        index_dex()


def test_edges_are_sorted_for_determinism(index):
    for callees in index.graph.edges.values():
        assert list(callees) == sorted(callees)


def test_multiple_dex_files_keep_source_provenance(dex_bytes):
    merged = index_dex(dex_bytes, dex_bytes)
    assert merged.complete is True
    assert merged.dex_coverage[0].entry == "classes1.dex"
    assert merged.dex_coverage[1].entry == "classes2.dex"
    assert merged.class_sources["AnalysisTest"] == ("classes1.dex", "classes2.dex")
    method = next(iter(merged.method_sources))
    assert merged.method_sources[method] == ("classes1.dex", "classes2.dex")


def test_apk_reports_each_dex_entry(dex_bytes):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("classes.dex", dex_bytes)
        zf.writestr("classes2.dex", dex_bytes)
    result = index_apk(buf.getvalue())
    assert [x.entry for x in result.dex_coverage] == ["classes.dex", "classes2.dex"]
    assert result.describe()["dex_indexed"] == 2
    assert result.complete is True


def test_corrupt_secondary_dex_makes_index_incomplete(dex_bytes):
    partial = index_dex(dex_bytes, b"not-a-dex")
    assert partial.classes == ("AnalysisTest",)
    assert partial.dex_coverage[0].status == "indexed"
    assert partial.dex_coverage[1].status == "failed"
    assert partial.complete is False
    assert partial.describe()["dex_failed"] == 1


def test_method_budget_marks_current_dex_truncated_and_later_dex_skipped(dex_bytes):
    partial = index_dex(dex_bytes, dex_bytes, max_methods=1)
    assert partial.truncated is True
    assert partial.dex_coverage[0].status == "truncated"
    assert partial.dex_coverage[1].status == "skipped"
    assert partial.complete is False


def test_duplicate_dex_zip_entries_are_rejected(dex_bytes):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("classes.dex", dex_bytes)
        zf.writestr("classes.dex", dex_bytes)
    with pytest.raises(DexIndexError, match="duplicate"):
        index_apk(buf.getvalue())


def test_method_reference_parser_keeps_names_containing_s():
    from mobius.adapters.dex import _parse_reference

    parsed = _parse_reference("Ljava/lang/String;->getString()Ljava/lang/String;")
    assert parsed == (
        "Ljava/lang/String;",
        "getString",
        "()Ljava/lang/String;",
    )



def test_dex_fixture_reports_selected_data_flow_scope_without_inventing_flows(index):
    assert index.data_flows == ()
    assert index.data_flow_methods == 0
    assert index.data_flow_complete is True



def test_androguard_cfg_extraction_uses_real_basic_blocks(dex_bytes):
    from androguard.core.dex import DEX
    from mobius.adapters.dex import _build_method_flow

    vm = DEX(dex_bytes)
    method = next(
        method
        for cls in vm.get_classes()
        for method in cls.get_methods()
        if method.get_code() is not None
    )
    flow = _build_method_flow(vm, method)

    assert flow is not None
    assert flow.blocks
    assert flow.entry == min(block.start for block in flow.blocks)
    assert all(
        successor in {block.start for block in flow.blocks}
        for block in flow.blocks
        for successor in block.successors
    )


# -- app-first budget allocation -------------------------------------------------


class _FakeMethod:
    def __init__(self, name, descriptor="()V"):
        self._name, self._descriptor = name, descriptor

    def get_name(self):
        return self._name

    def get_descriptor(self):
        return self._descriptor

    def get_code(self):
        return None


class _FakeClass:
    def __init__(self, descriptor, methods):
        self._name, self._methods = descriptor, list(methods)

    def get_name(self):
        return self._name

    def get_methods(self):
        return list(self._methods)


class _FakeDex:
    def __init__(self, classes):
        self._classes = list(classes)

    def get_classes(self):
        return list(self._classes)


def _fake_layout(monkeypatch):
    fakes = {
        b"lib-dex": _FakeDex([_FakeClass("Lcom/lib/Util;", [_FakeMethod(n) for n in ("a", "b", "c")])]),
        b"app-dex": _FakeDex([_FakeClass("Lcom/example/app/Main;", [_FakeMethod(n) for n in ("onCreate", "onStart")])]),
    }
    monkeypatch.setattr("androguard.core.dex.DEX", lambda raw: fakes[raw])


def test_app_package_entries_spend_the_budget_first(monkeypatch):
    _fake_layout(monkeypatch)
    idx = index_dex(b"lib-dex", b"app-dex", max_methods=3, app_package="com.example.app")
    assert idx.methods == 3
    assert idx.truncated is True
    # complete stays False, which is what keeps caller_check_absent unknown downstream
    assert idx.complete is False
    # coverage is reported in original source order, not admission order
    by_entry = {c.entry: c for c in idx.dex_coverage}
    assert [c.entry for c in idx.dex_coverage] == ["classes1.dex", "classes2.dex"]
    assert by_entry["classes2.dex"].status == "indexed"
    assert by_entry["classes2.dex"].methods == 2
    assert by_entry["classes1.dex"].status == "truncated"
    assert by_entry["classes1.dex"].methods == 1
    assert by_entry["classes1.dex"].error == "global method budget exhausted"
    assert "com.example.app.Main" in idx.classes
    assert idx.describe()["dex_truncated"] == 1
    # deterministic: identical inputs give identical allocation
    again = index_dex(b"lib-dex", b"app-dex", max_methods=3, app_package="com.example.app")
    assert again.describe() == idx.describe()
    assert [c.describe() for c in again.dex_coverage] == [c.describe() for c in idx.dex_coverage]


def test_unknown_or_missing_package_keeps_name_order(monkeypatch):
    _fake_layout(monkeypatch)
    for package in ("com.other", None):
        idx = index_dex(b"lib-dex", b"app-dex", max_methods=2, app_package=package)
        assert idx.methods == 2
        assert idx.truncated is True
        by_entry = {c.entry: c for c in idx.dex_coverage}
        # the library entry is cut at the budget and the app entry is skipped:
        # name order decides coverage when the package matches nothing (or is absent)
        assert by_entry["classes1.dex"].status == "truncated"
        assert by_entry["classes1.dex"].methods == 2
        assert by_entry["classes2.dex"].status == "skipped"
        assert by_entry["classes2.dex"].methods == 0


def test_apk_manifest_package_drives_prioritization(dex_bytes):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("AndroidManifest.xml", "<manifest package='AnalysisTest'/>")
        zf.writestr("classes.dex", dex_bytes)
        zf.writestr("classes2.dex", dex_bytes)
    result = index_apk(buf.getvalue(), max_methods=1)
    # the fixture class IS the manifest package, so both entries are app-bearing and
    # keep stable order: first entry truncated at the budget, second skipped
    assert result.truncated is True
    assert result.dex_coverage[0].status == "truncated"
    assert result.dex_coverage[1].status == "skipped"
    assert result.complete is False


def test_unreadable_manifest_never_blocks_indexing(dex_bytes):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("AndroidManifest.xml", b"\x03\x00\x08\x00 not a real manifest")
        zf.writestr("classes.dex", dex_bytes)
    result = index_apk(buf.getvalue())
    assert result.methods == index_dex(dex_bytes).methods
    assert result.complete is True


def test_oversized_entry_fails_before_parsing(monkeypatch, dex_bytes):
    from mobius.adapters import dex as dex_module

    monkeypatch.setattr(dex_module, "MAX_DEX_BYTES", 10)
    with pytest.raises(DexIndexError, match="no DEX entry could be indexed"):
        index_dex(dex_bytes)
