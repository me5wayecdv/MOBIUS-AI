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
