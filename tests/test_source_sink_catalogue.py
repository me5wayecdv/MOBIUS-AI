from __future__ import annotations

from pathlib import Path

import pytest

from mobius.core.sinks import (
    CATALOGUE_VERSION,
    GUARDS,
    SINKS,
    SOURCES,
    load_catalogue,
    sink_for,
    source_for,
)


def test_default_catalogue_loads_sources_sinks_and_guards():
    assert CATALOGUE_VERSION == 1
    assert source_for("Landroid/content/Intent;", "getStringExtra") is not None
    assert sink_for("Landroid/webkit/WebView;", "loadUrl") is not None
    assert ("Landroid/content/Context;", "checkCallingPermission") in GUARDS
    assert len(SOURCES) >= 7
    assert len(SINKS) >= 9


def test_source_and_sink_entries_include_maswe_masvs_and_provenance():
    source = source_for("Landroid/content/Intent;", "getData")
    sink = sink_for("Ldalvik/system/DexClassLoader;", "<init>")
    assert source is not None
    assert "MASWE-0029" in source.maswe
    assert "MASVS-PLATFORM-1" in source.masvs
    assert source.references
    assert sink is not None
    assert "MASWE-0049" in sink.maswe
    assert "MASVS-CODE-4" in sink.masvs
    assert sink.impact == "integrity"
    assert sink.confidence in {"low", "medium", "high"}
    webview_access = sink_for("Landroid/webkit/WebSettings;", "setAllowUniversalAccessFromFileURLs")
    assert webview_access is not None
    assert "MASWE-0034" in webview_access.maswe
    assert "MASVS-PLATFORM-2" in webview_access.masvs


def test_catalogue_extension_adds_rules_without_python_changes(tmp_path: Path):
    fixture = Path(__file__).parent / "fixtures" / "catalogue_extension.yaml"
    loaded = load_catalogue(fixture)
    assert loaded.catalogue_id == "test.extension"
    assert loaded.sources[0].id == "fixture-source"
    assert loaded.sinks[0].id == "fixture-sink"
    assert loaded.sinks[0].maswe == ("MASWE-0050",)


def test_negative_unknown_apis_do_not_match_by_substring():
    assert source_for("Landroid/content/Intent;", "getString") is None
    assert sink_for("Ljava/io/File;", "<init>") is None
    assert sink_for("Landroid/webkit/WebView;", "loadDataWithBaseURL") is None


def test_negative_non_security_relevant_value_reads_are_not_sinks():
    assert sink_for("Landroid/content/SharedPreferences;", "getString") is None
    assert sink_for("Landroid/content/Context;", "startActivity") is None
    assert sink_for("Ljava/lang/reflect/Method;", "invoke") is None


def test_invalid_catalogue_mapping_fails_closed(tmp_path: Path):
    bad = tmp_path / "bad.yaml"
    bad.write_text(
        "version: 1\ncatalogue_id: bad\nplatform: android\n"
        "sources:\n"
        "  - {id: external-input, class_descriptor: 'Lx/Input;', method: read, "
        "descriptor: '()Ljava/lang/String;', family: ipc, trust_boundary: external, "
        "maswe: [MASWE-9999], masvs: [MASVS-CODE-4], confidence: high, "
        "description: invalid mapping}\n"
        "sinks: []\nguards: []\n",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="unknown MASWE"):
        load_catalogue(bad)


def test_duplicate_api_key_is_rejected(tmp_path: Path):
    bad = tmp_path / "duplicate.yaml"
    bad.write_text(
        "version: 1\ncatalogue_id: bad\nplatform: android\n"
        "sources: []\nsinks:\n"
        "  - {id: sink-one, class_descriptor: 'Lx/Y;', method: run, family: x, "
        "maswe: [MASWE-0050], masvs: [MASVS-CODE-4], confidence: low, impact: unknown, description: one}\n"
        "  - {id: sink-two, class_descriptor: 'Lx/Y;', method: run, family: x, "
        "maswe: [MASWE-0050], masvs: [MASVS-CODE-4], confidence: low, impact: unknown, description: two}\n"
        "guards: []\n",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="duplicate sink API key"):
        load_catalogue(bad)
