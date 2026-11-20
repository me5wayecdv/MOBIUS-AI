"""Runtime-validation harness: the read-back path must accept both forms a
JSON column can take (dict via the ORM, raw string via a text() query on
sqlite) and must never normalize malformed JSON into a pass.
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path

import pytest

from mobius.adapters.android_manifest import parse_apk
from mobius.adapters.flow_adapt import adapt_code
from mobius.adapters.provider_payload import provider_analysis_payload
from mobius.core.providers import detect_provider_exposures

_SCRIPT = Path(__file__).parent.parent / "scripts" / "validate_provider_runtime.py"
_spec = importlib.util.spec_from_file_location("validate_provider_runtime", _SCRIPT)
runtime = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(runtime)


def _valid_state() -> tuple[dict, str]:
    apk = runtime.fixture_apk(runtime.FIXTURE_DEX.read_bytes())
    sha = hashlib.sha256(apk).hexdigest()
    surface = parse_apk(apk)
    methods, registers_sizes, superclasses, try_regions, ledger, origins = adapt_code(apk)
    payload = provider_analysis_payload(
        artifact_sha256=sha,
        package_name=surface.package_name,
        methods_adapted=len(methods),
        ledger=ledger,
        exposures=list(
            detect_provider_exposures(
                surface, methods, registers_sizes, superclasses, try_regions
            )
        ),
    )
    return payload, sha


def test_validated_result_accepts_dict_form() -> None:
    payload, sha = _valid_state()
    result = runtime.validated_result({"result_json": payload}, sha)
    assert result.package_name == "com.example"
    assert result.methods_adapted == payload["methods_adapted"]
    assert result.dex_complete


def test_validated_result_accepts_sqlite_string_form() -> None:
    payload, sha = _valid_state()
    stored = json.dumps(payload)
    from_str = runtime.validated_result({"result_json": stored}, sha)
    from_dict = runtime.validated_result({"result_json": payload}, sha)
    assert json.dumps(from_str.ledger, default=str) == json.dumps(
        from_dict.ledger, default=str
    )
    assert from_str.package_name == from_dict.package_name
    assert from_str.methods_adapted == from_dict.methods_adapted


def test_validated_result_rejects_malformed_json_string() -> None:
    _, sha = _valid_state()
    with pytest.raises(ValueError):
        runtime.validated_result({"result_json": "{not json"}, sha)


def test_validated_result_rejects_schema_invalid_payload() -> None:
    payload, sha = _valid_state()
    payload["schema_version"] = 2
    with pytest.raises(ValueError):
        runtime.validated_result({"result_json": payload}, sha)


def test_validated_result_rejects_wrong_digest() -> None:
    payload, _ = _valid_state()
    other_sha = "0" * 64
    with pytest.raises(ValueError, match="not bound"):
        runtime.validated_result({"result_json": payload}, other_sha)
    stored = json.dumps(payload)
    with pytest.raises(ValueError, match="not bound"):
        runtime.validated_result({"result_json": stored}, other_sha)
