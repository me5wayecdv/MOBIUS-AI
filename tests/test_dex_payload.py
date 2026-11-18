from __future__ import annotations

from dataclasses import replace

import hashlib
import pathlib
import zipfile
from io import BytesIO

import pytest

from mobius.adapters.dex import index_apk
from mobius.core.dataflow import DataFlowFinding
from mobius.core.reachability import MethodRef
from mobius.adapters.dex_payload import (
    code_index_payload,
    validate_dex_index_payload,
)


FIXTURE = pathlib.Path(__file__).parent / "fixtures" / "dex" / "AnalysisTest.dex"


def _apk() -> bytes:
    stream = BytesIO()
    with zipfile.ZipFile(stream, "w") as archive:
        archive.writestr("classes.dex", FIXTURE.read_bytes())
        archive.writestr("classes2.dex", FIXTURE.read_bytes())
    return stream.getvalue()


def test_dex_index_wire_format_round_trips_multidex_provenance():
    apk = _apk()
    digest = hashlib.sha256(apk).hexdigest()
    index = index_apk(apk)
    payload = code_index_payload(index, digest)
    import json
    encoded = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()

    restored = validate_dex_index_payload(encoded, digest)

    assert restored.classes == index.classes
    assert restored.methods == index.methods
    assert restored.complete is True
    assert [item.entry for item in restored.dex_coverage] == ["classes.dex", "classes2.dex"]
    assert restored.class_sources == index.class_sources
    assert restored.method_sources == index.method_sources
    assert restored.graph.edges == index.graph.edges
    assert restored.boundary == index.boundary
    assert restored.strings == index.strings


def test_dex_index_wire_format_rejects_wrong_apk_digest():
    apk = _apk()
    payload = code_index_payload(index_apk(apk), hashlib.sha256(apk).hexdigest())
    import json
    encoded = json.dumps(payload).encode()

    with pytest.raises(ValueError, match="not bound"):
        validate_dex_index_payload(encoded, "0" * 64)


def test_dex_index_wire_format_rejects_oversized_result():
    with pytest.raises(ValueError, match="size limit"):
        validate_dex_index_payload(b" " * (19 * 1024 * 1024 + 1), "0" * 64)


def test_dex_index_wire_format_rejects_unknown_fields():
    apk = _apk()
    payload = code_index_payload(index_apk(apk), hashlib.sha256(apk).hexdigest())
    payload["unexpected"] = "must not be accepted"
    import json
    with pytest.raises(ValueError, match="invalid schema"):
        validate_dex_index_payload(json.dumps(payload).encode(), hashlib.sha256(apk).hexdigest())



def test_data_flow_evidence_round_trips_through_worker_payload():
    apk = _apk()
    digest = hashlib.sha256(apk).hexdigest()
    index = index_apk(apk)
    finding = DataFlowFinding(
        method=MethodRef("com.example.Entry", "onCreate", "()V"),
        source_id="intent-string-extra",
        sink_id="webview-load",
        source_offset=12,
        sink_offset=48,
        sink_register=3,
        guard_ids_before=("check-calling-permission",),
        guard_ids_after=(),
        guard_dominates_sink=True,
        guard_outcome_verified=False,
    )
    enriched = replace(
        index,
        data_flows=(finding,),
        data_flow_methods=1,
        data_flow_complete=True,
    )
    import json
    encoded = json.dumps(
        code_index_payload(enriched, digest),
        separators=(",", ":"),
        sort_keys=True,
    ).encode()

    restored = validate_dex_index_payload(encoded, digest)

    assert restored.data_flows == (finding,)
    assert restored.data_flow_methods == 1
    assert restored.data_flow_complete is True
    assert restored.data_flows[0].assertion == "may-flow"



def test_data_flow_payload_rejects_confirmed_or_guard_verified_claims():
    apk = _apk()
    digest = hashlib.sha256(apk).hexdigest()
    payload = code_index_payload(index_apk(apk), digest)
    payload["data_flows"] = [{
        "method": {"class_name": "com.example.Entry", "name": "onCreate", "descriptor": "()V"},
        "source_id": "intent-string-extra",
        "sink_id": "webview-load",
        "source_offset": 0,
        "sink_offset": 8,
        "sink_register": 2,
        "guard_ids_before": [],
        "guard_ids_after": [],
        "guard_dominates_sink": False,
        "guard_outcome_verified": True,
        "assertion": "confirmed",
    }]
    import json
    with pytest.raises(ValueError, match="unsupported assertion"):
        validate_dex_index_payload(json.dumps(payload).encode(), digest)



def test_legacy_worker_payload_without_d015_fields_defaults_to_incomplete():
    apk = _apk()
    digest = hashlib.sha256(apk).hexdigest()
    payload = code_index_payload(index_apk(apk), digest)
    for key in (
        "data_flows",
        "data_flow_methods",
        "data_flow_truncated_methods",
        "data_flow_complete",
        "data_flow_limitations",
    ):
        payload.pop(key, None)
    import json
    restored = validate_dex_index_payload(json.dumps(payload).encode(), digest)

    assert restored.data_flows == ()
    assert restored.data_flow_methods == 0
    assert restored.data_flow_complete is False
