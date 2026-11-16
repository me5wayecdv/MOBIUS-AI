from __future__ import annotations

import hashlib
import pathlib
import zipfile
from io import BytesIO

import pytest

from mobius.adapters.dex import index_apk
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
