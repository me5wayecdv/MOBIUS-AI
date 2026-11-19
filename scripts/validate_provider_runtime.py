"""No-push runtime validation for the provider-analysis worker, against the
real OCI runner path (worker.runner -> OciBackend -> ToolRunner -> docker).

PREPARATION/CI USE ONLY. This script never pushes to, pulls from, or logs into
any external registry: the image reference is a loopback-only registry digest
prepared by the workflow (see validate-provider-worker-runtime.yml). It fails
loudly (exit 1) when docker is unavailable - there is no skip path that could
read as green.

What it proves, on fixed in-repo fixtures (tests/fixtures/dex/AnalysisTest.dex
wrapped in a minimal provider APK; no external/training APKs, no network in
the analysis path):

1. PIPELINE SUCCESS: a real provider_analysis job is seeded through
   IntakeService + WorkerQueue on a sqlite database migrated with
   `alembic upgrade head` (the deployed schema, not create_all), then executed
   by the unmodified `python -m mobius.worker.runner` one-shot path with the
   digest-pinned local image. Assertions:
   - runner exits 0 within the wall-clock bound (subprocess timeout);
   - the job row is succeeded;
   - staged_sha256 equals the sha256 of the exact fixture bytes AND the intake
     artifact digest (artifact binding, host-side anchor);
   - the stored result validates through the API's own
     validate_provider_analysis_payload against that digest (output contract);
   - result.package_name is the fixture package, methods_adapted > 0, and
     every ledger entry is parsed (happy-path ledger shape).
   SCOPE LIMIT, stated plainly: the fixture DEX contains no provider class,
   so exposures is expected empty. This run proves the isolated pipeline
   (manifest parse -> DEX adapt -> ledger -> payload -> API contract) through
   the real OCI runner; it does NOT prove provider-exposure semantics, which
   are covered by the API-level tests. No semantic verdict is claimed here.
2. DEGRADED INPUT: a second fixture is a VALID zip whose classes.dex is
   malformed (bad magic). Intake accepts it (valid archive, parseable text
   manifest); the worker records a failed-parse ledger entry instead of
   crashing. Assertions: runner exits 0, job row succeeded, the stored result
   validates through the API contract, at least one ledger entry is
   failed-parse, and dex_complete is False (degradation is visible, not
   masquerading as success or as an infrastructure error).

What is NOT asserted here: the OCI mount-isolation contract (covered by
scripts/oci_contract_probe.py against the recon image) and independent
proof of kernel-enforced network/resource kills (the runner's ToolLimits are
applied through the docker argv by the unmodified OciBackend; this script
asserts outcomes, not kernel enforcement).

Usage:
    validate_provider_runtime.py --image <name@sha256:digest> \
        --runtime-path /usr/bin/docker
Exit 0 = every assertion held; 1 = any failure (details on stderr).
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import zipfile
from datetime import datetime, timedelta, timezone
from io import BytesIO
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
FIXTURE_DEX = REPO / "tests" / "fixtures" / "dex" / "AnalysisTest.dex"

MANIFEST = (
    '<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.example">'
    "<application>"
    "<provider android:name='.NotesProvider' android:authorities='com.example.notes' "
    "android:exported='true'/>"
    "</application></manifest>"
)

# Not a DEX file: wrong magic and too short for a header. Parse fails cleanly.
MALFORMED_DEX = b"not-a-dex\x00\x01\x02\x03" * 8

IMAGE_REF = r"^[A-Za-z0-9./:_-]+@sha256:[0-9a-f]{64}$"


def fixture_apk(dex_bytes: bytes) -> bytes:
    stream = BytesIO()
    with zipfile.ZipFile(stream, "w") as archive:
        archive.writestr("AndroidManifest.xml", MANIFEST)
        archive.writestr("classes.dex", dex_bytes)
    return stream.getvalue()


def fail(msg: str) -> None:
    print(f"FAIL: {msg}", file=sys.stderr)
    sys.exit(1)


def seed(db_url: str, artifact_root: Path, apk: bytes, objective: str):
    from sqlalchemy import text
    from mobius.adapters.db import make_engine, make_session_factory
    from mobius.services.artifacts import ArtifactStore
    from mobius.services.intake import IntakeService
    from mobius.services.worker_queue import WorkerQueue

    engine = make_engine(db_url)
    factory = make_session_factory(engine)
    store = ArtifactStore(str(artifact_root))
    expires = (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()
    with factory() as session:
        intake = IntakeService(session, store)
        app, _ = intake.create_application(apk, "fixture.apk", uploaded_by="runtime-validation")
        auth = intake.create_authorization(
            apk_sha256=app.sha256, target_package="com.example",
            scope_text="Static analysis of the supplied fixture APK only.",
            statement="I am authorized to analyze this APK.",
            max_intensity=0, granted_by="runtime-validation", expires_at=expires,
        )
        scan = intake.create_investigation(
            application_id=app.id, authorization_id=auth.id,
            objective=objective, intensity=0, created_by="runtime-validation")
        intake.start(scan.id)
        # enqueue_provider_analysis requires SURFACE_READY; recon is not what
        # this validation exercises, so move the state directly (same as tests).
        session.execute(text(
            "UPDATE investigations SET state = 'SURFACE_READY' WHERE id = :i"),
            {"i": scan.id})
        session.commit()
        scan_id, artifact_key, sha = scan.id, app.artifact_key, app.sha256
    with factory() as session:
        job = WorkerQueue(session).enqueue_provider_analysis(scan_id, artifact_key)
        session.commit()
        job_id = job.id
    engine.dispose()
    return scan_id, job_id, sha


def run_runner(db_url: str, artifact_root: Path, workspace_root: Path,
               image: str, runtime_path: str, timeout_s: int) -> subprocess.CompletedProcess:
    env = dict(os.environ)
    env.update({
        "MOBIUS_WORKER_DB_URL": db_url,
        "MOBIUS_ARTIFACT_ROOT": str(artifact_root),
        "MOBIUS_WORKSPACE_ROOT": str(workspace_root),
        "MOBIUS_OCI_RUNTIME": runtime_path,
        "MOBIUS_PROVIDER_IMAGE": image,
        "MOBIUS_WORKER_ONCE": "1",
    })
    return subprocess.run(
        [sys.executable, "-m", "mobius.worker.runner"],
        env=env, cwd=REPO, capture_output=True, timeout=timeout_s)


def job_state(db_url: str, job_id: str):
    from sqlalchemy import text
    from mobius.adapters.db import make_engine
    engine = make_engine(db_url)
    with engine.connect() as conn:
        row = conn.execute(text(
            "SELECT status, result_json, error_code, error_detail, staged_sha256 "
            "FROM worker_jobs WHERE id = :i"), {"i": job_id}).mappings().first()
    engine.dispose()
    return dict(row) if row else None


def validated_result(state, sha: str):
    from mobius.adapters.provider_payload import validate_provider_analysis_payload
    result_json = state["result_json"]
    # The raw text() read-back returns a sqlite JSON column as a string;
    # decode before re-encoding or the DTO sees a JSON string literal.
    if isinstance(result_json, str):
        result_json = json.loads(result_json)
    return validate_provider_analysis_payload(
        json.dumps(result_json).encode(), sha)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--image", required=True,
                        help="loopback-registry name@sha256:<manifest digest> ref")
    parser.add_argument("--runtime-path", default=None,
                        help="absolute path to the docker CLI (default: resolved via PATH)")
    parser.add_argument("--timeout-seconds", type=int, default=600)
    args = parser.parse_args()

    if not re.fullmatch(IMAGE_REF, args.image):
        fail("image ref must be a digest-pinned reference (name@sha256:<64 hex>)")
    runtime_path = args.runtime_path or shutil.which("docker")
    if not runtime_path or not Path(runtime_path).is_absolute() or not Path(runtime_path).is_file():
        fail("docker CLI not found at an absolute path; runtime validation cannot run "
             "(no skip path)")
    if not FIXTURE_DEX.exists():
        fail(f"fixture missing: {FIXTURE_DEX}")

    checks: list[str] = []
    with tempfile.TemporaryDirectory(prefix="mobius-rt-") as tmp:
        tmp_path = Path(tmp)
        artifact_root = tmp_path / "artifacts"
        workspace_root = tmp_path / "work"
        db_url = f"sqlite+pysqlite:///{tmp_path}/rt.db"

        env = dict(os.environ, MOBIUS_DB_URL=db_url)
        mig = subprocess.run(["alembic", "upgrade", "head"], cwd=REPO, env=env,
                             capture_output=True, timeout=120)
        if mig.returncode != 0:
            fail(f"alembic upgrade head failed: {mig.stderr.decode()[-500:]}")
        checks.append("schema: alembic upgrade head on a fresh sqlite DB")

        # 1. pipeline success path
        apk = fixture_apk(FIXTURE_DEX.read_bytes())
        scan_id, job_id, sha = seed(db_url, artifact_root, apk,
                                    "runtime validation pipeline success path")
        proc = run_runner(db_url, artifact_root, workspace_root, args.image,
                          runtime_path, args.timeout_seconds)
        if proc.returncode != 0:
            fail(f"runner crashed on the valid fixture: {proc.stderr.decode()[-800:]}")
        state = job_state(db_url, job_id)
        if not state or state["status"] != "succeeded":
            fail(f"valid-fixture job not succeeded: {state}")
        if state["staged_sha256"] != hashlib.sha256(apk).hexdigest():
            fail("staged_sha256 does not bind the fixture bytes")
        if state["staged_sha256"] != sha:
            fail("staged_sha256 does not equal the intake artifact digest")
        try:
            result = validated_result(state, sha)
        except Exception as exc:
            fail(f"stored result fails the API output contract: {exc}")
        if result.artifact_sha256 != sha:
            fail("result artifact digest mismatch")
        if result.package_name != "com.example":
            fail(f"unexpected package_name: {result.package_name}")
        if result.methods_adapted <= 0:
            fail("happy fixture adapted no methods; fixture is not exercising the adapter")
        if not result.ledger or any(b.status != "parsed" for b in result.ledger):
            fail(f"happy fixture ledger not fully parsed: {result.ledger}")
        # Scope limit: the fixture DEX has no provider class, so no exposure
        # semantics are asserted or claimed here (API-level tests own those).
        checks.append(
            "success: job succeeded, digest-bound, API-contract-valid result; "
            "package/methods/parsed-ledger asserted (pipeline proof, no exposure semantics)")

        # 2. degraded input path: valid zip, malformed DEX
        bad_apk = fixture_apk(MALFORMED_DEX)
        _, bad_job_id, bad_sha = seed(db_url, artifact_root, bad_apk,
                                      "runtime validation degraded input path")
        proc = run_runner(db_url, artifact_root, workspace_root, args.image,
                          runtime_path, args.timeout_seconds)
        if proc.returncode != 0:
            fail(f"runner crashed on the degraded fixture: {proc.stderr.decode()[-800:]}")
        state = job_state(db_url, bad_job_id)
        if not state or state["status"] != "succeeded":
            fail(f"degraded-fixture job should succeed with a degraded ledger, got: {state}")
        try:
            bad_result = validated_result(state, bad_sha)
        except Exception as exc:
            fail(f"degraded result fails the API output contract: {exc}")
        if not any(b.status == "failed-parse" for b in bad_result.ledger):
            fail(f"malformed DEX did not produce a failed-parse ledger entry: "
                 f"{bad_result.ledger}")
        if bad_result.dex_complete:
            fail("degraded ledger reported complete coverage")
        checks.append(
            "degraded: malformed DEX -> failed-parse ledger entry, dex_complete False, "
            "contract-valid, no crash")

    for c in checks:
        print(f"PASS: {c}")
    print(json.dumps({"ok": True, "checks": checks}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
