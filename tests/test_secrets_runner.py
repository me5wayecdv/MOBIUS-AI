"""Secrets-analysis worker dispatch and bounded output handling.

No OCI runtime is needed: _tool_for is pure configuration and
_output_from_tool_result operates on an in-memory ToolRun. These tests prove
the fail-closed shapes (missing/non-digest image, truncation, bad schema
marker); they do NOT prove container execution, which only the no-push
runtime validation script covers.
"""

from __future__ import annotations

import json

import pytest

from mobius.adapters.secrets_payload import MAX_SECRETS_JSON_BYTES
from mobius.services.tool_runner import ToolRun
from mobius.worker.runner import _SECRETS_BINARY, _output_from_tool_result, _tool_for


IMAGE = "ghcr.io/me5wayecdv/mobius-secrets@sha256:" + "c" * 64


def _result(**overrides):
    fields = {
        "tool": "secrets_analysis",
        "version": "mobius-secrets-analysis-v1",
        "status": "ok",
        "exit_code": 0,
        "stdout": json.dumps({"schema_version": 1, "artifact_sha256": "a" * 64}).encode(),
        "stderr_tail": "",
        "duration_ms": 1,
        "truncated": False,
    }
    fields.update(overrides)
    return ToolRun(**fields)


def test_secrets_job_uses_only_the_registered_image_and_networkless_limits(monkeypatch):
    monkeypatch.setenv("MOBIUS_SECRETS_IMAGE", IMAGE)
    binary, image, spec = _tool_for("secrets_analysis", "/usr/bin/podman")

    assert binary == _SECRETS_BINARY
    assert image == IMAGE
    assert spec.name == "secrets_analysis"
    assert spec.limits.network_enabled is False
    assert spec.limits.memory_mb == 4096
    assert spec.limits.timeout_seconds == 900
    assert spec.argv_for({}) == (_SECRETS_BINARY, "--input", "/work/input.apk")
    # Oversize stdout is truncated by the runner ABOVE the worker's own
    # self-cap, so the worker's bounded error wins over silent truncation.
    assert spec.limits.max_output_bytes > MAX_SECRETS_JSON_BYTES


def test_secrets_dispatch_fails_closed_without_an_image(monkeypatch):
    monkeypatch.delenv("MOBIUS_SECRETS_IMAGE", raising=False)
    with pytest.raises(RuntimeError, match="MOBIUS_SECRETS_IMAGE must be configured"):
        _tool_for("secrets_analysis", "/usr/bin/podman")


def test_secrets_dispatch_requires_an_immutable_image_reference(monkeypatch):
    monkeypatch.setenv("MOBIUS_SECRETS_IMAGE", "ghcr.io/example/mobius-secrets:latest")
    with pytest.raises(ValueError, match="immutable sha256"):
        _tool_for("secrets_analysis", "/usr/bin/podman")


def test_secrets_output_accepts_schema_marker():
    out = _output_from_tool_result("secrets_analysis", _result())
    assert out["schema_version"] == 1


def test_secrets_output_rejects_a_wrong_schema_marker():
    bad = _result(stdout=json.dumps({"schema_version": 2}).encode())
    with pytest.raises(RuntimeError, match="unsupported result schema"):
        _output_from_tool_result("secrets_analysis", bad)


def test_secrets_output_rejects_a_missing_schema_marker():
    bad = _result(stdout=json.dumps({"artifact_sha256": "a" * 64}).encode())
    with pytest.raises(RuntimeError, match="unsupported result schema"):
        _output_from_tool_result("secrets_analysis", bad)


def test_secrets_output_fails_closed_on_truncation():
    # Oversize container output reaches here ONLY as truncated=True; parsing
    # partial JSON as a payload is refused.
    with pytest.raises(RuntimeError, match="output_truncated=True"):
        _output_from_tool_result("secrets_analysis", _result(truncated=True))


def test_secrets_output_fails_closed_on_nonzero_exit():
    with pytest.raises(RuntimeError, match="isolated secrets_analysis failed"):
        _output_from_tool_result("secrets_analysis", _result(exit_code=3))


def test_secrets_output_fails_closed_on_backend_error():
    with pytest.raises(RuntimeError, match="isolated secrets_analysis failed"):
        _output_from_tool_result("secrets_analysis", _result(status="error", exit_code=None))


# ---------------------------------------------------------------------------
# run_once terminal state (real DB + artifact store, no OCI contact)
# ---------------------------------------------------------------------------

def _seed_queued_secrets_job(db_url, artifact_root, tmp_path):
    """Seed an authorized SURFACE_READY scan and a queued secrets job through
    the real intake/queue services, on a file-backed sqlite DB (run_once
    opens its own engine, so the in-memory conftest DB cannot be used)."""
    from datetime import datetime, timedelta, timezone
    from sqlalchemy import text
    from mobius.adapters.db import init_schema, make_engine, make_session_factory
    from mobius.services.artifacts import ArtifactStore
    from mobius.services.intake import IntakeService
    from mobius.services.worker_queue import WorkerQueue
    from conftest import make_apk

    engine = make_engine(db_url)
    init_schema(engine)
    factory = make_session_factory(engine)
    store = ArtifactStore(str(artifact_root))
    expires = (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()
    with factory() as session:
        intake = IntakeService(session, store)
        app, _ = intake.create_application(make_apk(), "fixture.apk", uploaded_by="t")
        auth = intake.create_authorization(
            apk_sha256=app.sha256, target_package="com.example",
            scope_text="Static analysis only.",
            statement="I am authorized to analyze this APK.",
            max_intensity=0, granted_by="t", expires_at=expires)
        scan = intake.create_investigation(
            application_id=app.id, authorization_id=auth.id,
            objective="secrets run_once terminal state", intensity=0, created_by="t")
        intake.start(scan.id)
        # enqueue requires SURFACE_READY; the recon run is not what these
        # tests exercise, so move the state directly (same as other tests).
        session.execute(text(
            "UPDATE investigations SET state = 'SURFACE_READY' WHERE id = :i"),
            {"i": scan.id})
        session.commit()
        job = WorkerQueue(session).enqueue_secrets_analysis(scan.id, app.artifact_key)
        session.commit()
        job_id, scan_id = job.id, scan.id
    engine.dispose()
    return job_id, scan_id


def _run_env(monkeypatch, db_url, artifact_root, workspace_root):
    monkeypatch.setenv("MOBIUS_WORKER_DB_URL", db_url)
    monkeypatch.setenv("MOBIUS_ARTIFACT_ROOT", str(artifact_root))
    monkeypatch.setenv("MOBIUS_WORKSPACE_ROOT", str(workspace_root))
    monkeypatch.setenv("MOBIUS_OCI_RUNTIME", "/usr/bin/true")


def _job_row(db_url, job_id):
    from sqlalchemy import text
    from mobius.adapters.db import make_engine
    engine = make_engine(db_url)
    with engine.connect() as conn:
        row = conn.execute(text(
            "SELECT status, error_code, error_detail, result_json, staged_sha256 "
            "FROM worker_jobs WHERE id = :i"), {"i": job_id}).mappings().first()
    engine.dispose()
    return dict(row)


def test_run_once_missing_image_fails_terminally_with_no_result(tmp_path, monkeypatch):
    """The documented missing-image lifecycle, proven at run_once level:
    claimed -> _tool_for raises -> terminal failed, bounded config error, no
    stored result, staged input cleaned up."""
    db_url = f"sqlite+pysqlite:///{tmp_path}/w.db"
    artifact_root = tmp_path / "artifacts"
    workspace_root = tmp_path / "work"
    job_id, scan_id = _seed_queued_secrets_job(db_url, artifact_root, tmp_path)
    _run_env(monkeypatch, db_url, artifact_root, workspace_root)
    monkeypatch.delenv("MOBIUS_SECRETS_IMAGE", raising=False)

    from mobius.worker.runner import run_once
    assert run_once() is True

    row = _job_row(db_url, job_id)
    assert row["status"] == "failed"
    assert row["error_code"] == "RuntimeError"
    assert "MOBIUS_SECRETS_IMAGE must be configured" in row["error_detail"]
    assert row["result_json"] is None
    # staged_sha256 is only persisted on success (fail() never records it),
    # so it is NULL here - measured behavior, not an anchor guarantee.
    assert row["staged_sha256"] is None
    assert not (workspace_root / scan_id / "input.apk").exists()


def test_run_once_invalid_output_fails_terminally_with_no_result(tmp_path, monkeypatch):
    """A configured worker whose container output fails the marker check:
    terminal failed, bounded error, no stored result, staged cleanup."""
    db_url = f"sqlite+pysqlite:///{tmp_path}/w.db"
    artifact_root = tmp_path / "artifacts"
    workspace_root = tmp_path / "work"
    job_id, scan_id = _seed_queued_secrets_job(db_url, artifact_root, tmp_path)
    _run_env(monkeypatch, db_url, artifact_root, workspace_root)
    monkeypatch.setenv("MOBIUS_SECRETS_IMAGE", IMAGE)

    bad = _result(stdout=json.dumps({"schema_version": 2}).encode())

    class FakeRunner:
        def __init__(self, **kwargs):
            pass

        def invoke(self, *, investigation_id, tool, args):
            return bad

    monkeypatch.setattr("mobius.worker.runner.ToolRunner", FakeRunner)

    from mobius.worker.runner import run_once
    assert run_once() is True

    row = _job_row(db_url, job_id)
    assert row["status"] == "failed"
    assert row["error_code"] == "RuntimeError"
    assert "unsupported result schema" in row["error_detail"]
    assert row["result_json"] is None
    assert not (workspace_root / scan_id / "input.apk").exists()


def test_run_once_truncated_output_never_reaches_storage(tmp_path, monkeypatch):
    """Oversize container output arrives truncated; the job fails closed and
    NO partial payload is stored."""
    db_url = f"sqlite+pysqlite:///{tmp_path}/w.db"
    artifact_root = tmp_path / "artifacts"
    workspace_root = tmp_path / "work"
    job_id, scan_id = _seed_queued_secrets_job(db_url, artifact_root, tmp_path)
    _run_env(monkeypatch, db_url, artifact_root, workspace_root)
    monkeypatch.setenv("MOBIUS_SECRETS_IMAGE", IMAGE)

    truncated = _result(truncated=True,
                        stdout=b'{"schema_version": 1, "artifact_sha256": "aa')

    class FakeRunner:
        def __init__(self, **kwargs):
            pass

        def invoke(self, *, investigation_id, tool, args):
            return truncated

    monkeypatch.setattr("mobius.worker.runner.ToolRunner", FakeRunner)

    from mobius.worker.runner import run_once
    assert run_once() is True

    row = _job_row(db_url, job_id)
    assert row["status"] == "failed"
    assert "output_truncated=True" in row["error_detail"]
    assert row["result_json"] is None


# ---------------------------------------------------------------------------
# old-kind helper regressions (the extraction must not change them)
# ---------------------------------------------------------------------------

def test_recon_output_still_requires_a_recognizable_manifest():
    ok = _result(tool="recon_manifest", stdout=b'<?xml version="1.0"?><manifest package="x"/>')
    assert _output_from_tool_result("recon_manifest", ok)["manifest_xml"].startswith("<?xml")
    bad = _result(tool="recon_manifest", stdout=b"not xml at all")
    with pytest.raises(RuntimeError, match="no recognizable XML manifest"):
        _output_from_tool_result("recon_manifest", bad)


def test_dex_output_still_requires_schema_marker():
    ok = _result(tool="dex_index", stdout=json.dumps({"schema_version": 1, "methods": []}).encode())
    assert _output_from_tool_result("dex_index", ok)["schema_version"] == 1
    bad = _result(tool="dex_index", stdout=json.dumps({"schema_version": 9}).encode())
    with pytest.raises(RuntimeError, match="unsupported result schema"):
        _output_from_tool_result("dex_index", bad)


def test_provider_output_still_requires_schema_marker():
    ok = _result(tool="provider_analysis",
                 stdout=json.dumps({"schema_version": 1, "exposures": []}).encode())
    assert _output_from_tool_result("provider_analysis", ok)["schema_version"] == 1
    bad = _result(tool="provider_analysis", stdout=json.dumps({"exposures": []}).encode())
    with pytest.raises(RuntimeError, match="unsupported result schema"):
        _output_from_tool_result("provider_analysis", bad)


def test_unknown_kind_still_rejected_after_extraction():
    with pytest.raises(RuntimeError, match="unsupported worker job kind"):
        _output_from_tool_result("arbitrary", _result(tool="arbitrary"))


# -- exit-4 explicit service-limit mapping (shared runner, all kinds) ---------

def test_exit_4_maps_to_fixed_service_limit_token_for_every_kind():
    from mobius.worker.runner import WorkerServiceLimitExceeded

    for kind in ("recon_manifest", "dex_index", "provider_analysis",
                 "secrets_analysis"):
        res = _result(tool=kind, status="error", exit_code=4,
                      stderr_tail="SENSITIVE-WORKER-PROSE")
        with pytest.raises(WorkerServiceLimitExceeded) as excinfo:
            _output_from_tool_result(kind, res)
        # fixed non-sensitive token: class name is the stored error_code
        assert type(excinfo.value).__name__ == "WorkerServiceLimitExceeded"
        assert "SENSITIVE-WORKER-PROSE" not in str(excinfo.value)
        assert "service limit" in str(excinfo.value)


def test_exit_4_is_not_a_limit_token_when_output_truncated():
    from mobius.worker.runner import WorkerServiceLimitExceeded

    res = _result(status="error", exit_code=4, truncated=True)
    with pytest.raises(RuntimeError, match="isolated secrets_analysis failed") as e:
        _output_from_tool_result("secrets_analysis", res)
    assert not isinstance(e.value, WorkerServiceLimitExceeded)


def test_exit_4_is_not_a_limit_token_when_status_not_error():
    from mobius.worker.runner import WorkerServiceLimitExceeded

    for status in ("ok", "timeout", "killed", "unavailable"):
        res = _result(status=status, exit_code=4)
        with pytest.raises(RuntimeError) as e:
            _output_from_tool_result("secrets_analysis", res)
        assert not isinstance(e.value, WorkerServiceLimitExceeded)


def test_non_4_and_missing_exit_codes_are_not_limit_tokens():
    from mobius.worker.runner import WorkerServiceLimitExceeded

    for code in (None, 1, 2, 3, 5, -4):
        res = _result(status="error", exit_code=code)
        with pytest.raises(RuntimeError) as e:
            _output_from_tool_result("secrets_analysis", res)
        assert not isinstance(e.value, WorkerServiceLimitExceeded)
