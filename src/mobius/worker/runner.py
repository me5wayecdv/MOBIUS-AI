"""Queue consumer for isolated manifest, DEX and JADX analysis workers.

The worker reads content-addressed APK objects and updates worker_jobs only. It never
queries investigations, users, authorizations, findings, evidence, or event tables.
"""
from __future__ import annotations

import hashlib

import os
import re
import socket
import time
from pathlib import Path

from pydantic import BaseModel, ConfigDict

from ..adapters.db import make_engine, make_session_factory
from ..services.artifacts import ArtifactStore
from ..services.errors import ScanStateConflict
from ..services.oci_backend import OciBackend
from ..services.tool_runner import ToolLimits, ToolRunner, ToolSpec
from ..services.worker_queue import WorkerQueue

_RECON_BINARY = "/usr/local/bin/mobius-recon-manifest"
_DEX_BINARY = "/usr/local/bin/mobius-dex-index"
_PROVIDER_BINARY = "/usr/local/bin/mobius-provider-analysis"
_SECRETS_BINARY = "/usr/local/bin/mobius-secrets-analysis"


class EmptyArgs(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


def _required(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise RuntimeError(f"{name} must be configured")
    return value


def _tool_for(kind: str, runtime: str) -> tuple[str, str, ToolSpec]:
    if kind == "recon_manifest":
        binary = _RECON_BINARY
        image = _required("MOBIUS_RECON_IMAGE")
        if not re.fullmatch(r"[A-Za-z0-9./:_-]+@sha256:[0-9a-f]{64}", image):
            raise ValueError("worker images must be immutable sha256 digest references")
        spec = ToolSpec(
            name="recon_manifest",
            binary=binary,
            version="mobius-recon-manifest-v1",
            args_model=EmptyArgs,
            build_argv=lambda _args: (binary, "--input", "/work/input.apk"),
            limits=ToolLimits(
                timeout_seconds=90, memory_mb=768, cpu_seconds=60,
                max_output_bytes=12 * 1024 * 1024, network_enabled=False,
            ),
        )
        return binary, image, spec
    if kind == "dex_index":
        binary = _DEX_BINARY
        image = _required("MOBIUS_DEX_IMAGE")
        if not re.fullmatch(r"[A-Za-z0-9./:_-]+@sha256:[0-9a-f]{64}", image):
            raise ValueError("worker images must be immutable sha256 digest references")
        spec = ToolSpec(
            name="dex_index",
            binary=binary,
            version="mobius-dex-index-v1",
            args_model=EmptyArgs,
            build_argv=lambda _args: (binary, "--input", "/work/input.apk", "--max-methods", "50000"),
            limits=ToolLimits(
                timeout_seconds=900, memory_mb=4096, cpu_seconds=600,
                max_output_bytes=19 * 1024 * 1024, network_enabled=False,
            ),
        )
        return binary, image, spec
    if kind == "provider_analysis":
        binary = _PROVIDER_BINARY
        image = _required("MOBIUS_PROVIDER_IMAGE")
        if not re.fullmatch(r"[A-Za-z0-9./:_-]+@sha256:[0-9a-f]{64}", image):
            raise ValueError("worker images must be immutable sha256 digest references")
        spec = ToolSpec(
            name="provider_analysis",
            binary=binary,
            version="mobius-provider-analysis-v1",
            args_model=EmptyArgs,
            build_argv=lambda _args: (binary, "--input", "/work/input.apk"),
            limits=ToolLimits(
                timeout_seconds=900, memory_mb=4096, cpu_seconds=600,
                max_output_bytes=6 * 1024 * 1024, network_enabled=False,
            ),
        )
        return binary, image, spec
    if kind == "secrets_analysis":
        binary = _SECRETS_BINARY
        image = _required("MOBIUS_SECRETS_IMAGE")
        if not re.fullmatch(r"[A-Za-z0-9./:_-]+@sha256:[0-9a-f]{64}", image):
            raise ValueError("worker images must be immutable sha256 digest references")
        spec = ToolSpec(
            name="secrets_analysis",
            binary=binary,
            version="mobius-secrets-analysis-v1",
            args_model=EmptyArgs,
            build_argv=lambda _args: (binary, "--input", "/work/input.apk"),
            limits=ToolLimits(
                # The worker self-caps its JSON at MAX_SECRETS_JSON_BYTES
                # (4 MiB) before writing (worker-asserted behavior: it holds
                # only while the image contains this exact worker code);
                # the runner budget stays above it so the worker's own
                # bounded error wins over truncation.
                timeout_seconds=900, memory_mb=4096, cpu_seconds=600,
                max_output_bytes=6 * 1024 * 1024, network_enabled=False,
            ),
        )
        return binary, image, spec
    raise RuntimeError(f"unsupported worker job kind: {kind}")


class WorkerServiceLimitExceeded(RuntimeError):
    """Worker exit 4: the input exceeded the service's explicit limits.

    Every registered worker kind documents exit 4 as its explicit bound or
    budget refusal (method bound or output budget); the generic wording is
    deliberate - the specific cause is never asserted from the exit code
    alone. Stored as the job's error_code through the existing class-name
    mechanism; the job outcome stays failed. A new worker kind MUST keep
    this exit-4 meaning for the mapping to stay truthful.
    """


def _output_from_tool_result(kind: str, result) -> dict:
    """Bounded output handling for every isolated job kind.

    A truncated or non-ok run NEVER reaches the payload contract: the
    runner's max_output_bytes cap truncates oversized stdout and marks the
    result, and this check fails the job instead of parsing partial JSON.
    Each kind then gets a syntax + schema-marker check only; the API applies
    the full schema, bounds and artifact-digest validation at apply time.
    """
    if result.status != "ok" or result.exit_code != 0 or result.truncated:
        # Exit 4 is the worker-documented explicit service-limit refusal, but
        # only when the container genuinely ran and exited on its own
        # (status "error" = nonzero exit) with UNTRUNCATED output: a timeout,
        # kill, truncation or any other code can never be reclassified as a
        # benign limit refusal. Fixed message only - no stderr tail, so the
        # stored outcome carries no worker prose.
        if (result.status == "error" and result.exit_code == 4
                and not result.truncated):
            raise WorkerServiceLimitExceeded(
                f"isolated {kind} reported an explicit service limit (exit 4); "
                "the job stays failed - bound or budget refusal, never a verdict"
            )
        raise RuntimeError(
            f"isolated {kind} failed: {result.status}; output_truncated={result.truncated}; "
            f"{result.stderr_tail}"
        )
    if kind == "recon_manifest":
        value = result.stdout.decode("utf-8", errors="strict")
        if not value.startswith("<?xml") and "<manifest" not in value[:2048]:
            raise RuntimeError("isolated RECON returned no recognizable XML manifest")
        return {"manifest_xml": value}
    if kind == "dex_index":
        # Validate JSON syntax and size here; the API performs the full schema and
        # artifact-digest validation before accepting or applying the result.
        import json
        value = json.loads(result.stdout.decode("utf-8", errors="strict"))
        if not isinstance(value, dict) or value.get("schema_version") != 1:
            raise RuntimeError("isolated DEX worker returned an unsupported result schema")
        return value
    if kind == "provider_analysis":
        # Same split as dex_index: syntax + schema marker here; the API
        # applies full schema, bounds and artifact-digest validation.
        import json
        value = json.loads(result.stdout.decode("utf-8", errors="strict"))
        if not isinstance(value, dict) or value.get("schema_version") != 1:
            raise RuntimeError(
                "isolated provider-analysis worker returned an unsupported result schema"
            )
        return value
    if kind == "secrets_analysis":
        # Same split as provider_analysis: syntax + schema marker
        # here; the API's apply route applies the full schema,
        # bounds, artifact-digest and zip-metadata anchors.
        import json
        value = json.loads(result.stdout.decode("utf-8", errors="strict"))
        if not isinstance(value, dict) or value.get("schema_version") != 1:
            raise RuntimeError(
                "isolated secrets-analysis worker returned an unsupported result schema"
            )
        return value
    raise RuntimeError(f"unsupported worker job kind: {kind}")


#: Reason recorded on every held jadx_decompile job; asserted by regression tests.
JADX_OUTPUT_HOLD_REASON = (
    "JADX output-writing is held: no verified file-output mount contract "
    "or output-tree cleanup; the stdout-only OCI contract cannot run JADX"
)


def _run_jadx_job() -> None:
    """HOLD: JADX is the one file-output tool, and the OCI backend exposes no
    writable host path at all (stdout-only contract, verified by the CI runtime
    probe). A writable-outputs contract for JADX and the cleanup of the
    container-uid-owned output tree are unverified, so this refuses to run instead
    of silently writing to the ephemeral tmpfs and reporting an empty/invalid
    output after the fact. The held implementation (writable outputs bind +
    adapter call) is in the branch's PR history; re-enable only with a reviewed
    file-output mount contract and a verified cleanup path. Enqueue stays gated
    on an approved immutable JADX image reference (MOBIUS_JADX_IMAGE; image
    unpublished)."""
    raise RuntimeError(JADX_OUTPUT_HOLD_REASON)


def run_once() -> bool:
    db_url = _required("MOBIUS_WORKER_DB_URL")
    artifact_root = Path(_required("MOBIUS_ARTIFACT_ROOT")).resolve()
    workspace_root = Path(_required("MOBIUS_WORKSPACE_ROOT")).resolve()
    runtime = _required("MOBIUS_OCI_RUNTIME")
    worker_id = os.environ.get("MOBIUS_WORKER_ID") or f"{socket.gethostname()}-{os.getpid()}"

    engine = make_engine(db_url)
    factory = make_session_factory(engine)
    claim_session = factory()
    try:
        job = WorkerQueue(claim_session).claim(worker_id)
        if job is None:
            claim_session.rollback()
            return False
        job_id, scan_id, artifact_key, kind = job.id, job.investigation_id, job.artifact_key, job.kind
        claim_session.commit()
    except Exception:
        claim_session.rollback()
        raise
    finally:
        claim_session.close()

    input_path: Path | None = None
    try:
        payload = ArtifactStore(artifact_root).get(artifact_key)
        # Host-side anchor: digest of the exact bytes the container will see,
        # computed before and outside the container. Stored with the result so
        # the API can compare it against its own anchors at apply time.
        staged_sha256 = hashlib.sha256(payload).hexdigest()
        workspace_root.mkdir(parents=True, exist_ok=True)
        workspace = workspace_root / scan_id
        if workspace.is_symlink():
            raise RuntimeError("worker workspace must not be a symlink")
        workspace.mkdir(mode=0o700, parents=True, exist_ok=True)
        input_path = workspace / "input.apk"
        if input_path.exists() or input_path.is_symlink():
            input_path.unlink()
        input_path.write_bytes(payload)
        input_path.chmod(0o444)

        if kind == "jadx_decompile":
            _run_jadx_job()
        else:
            binary, image, spec = _tool_for(kind, runtime)
            backend = OciBackend(runtime=runtime, binary_images={binary: image},
                                 run_label=os.environ.get("MOBIUS_CANARY_RUN_ID") or None)
            runner = ToolRunner(workspace_root=workspace_root, backend=backend, tools=(spec,))
            result = runner.invoke(investigation_id=scan_id, tool=spec.name, args={})
            output = _output_from_tool_result(kind, result)

        session = factory()
        try:
            WorkerQueue(session).succeed(job_id, worker_id, output,
                                         staged_sha256=staged_sha256)
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()
    except Exception as exc:
        session = factory()
        try:
            WorkerQueue(session).fail(job_id, worker_id, type(exc).__name__, str(exc))
            session.commit()
        except ScanStateConflict:
            # Ownership was lost (lease expired, job reclaimed): the new owner
            # decides this job's outcome. A late result must not crash the
            # error path or overwrite another worker's state.
            session.rollback()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()
    finally:
        if input_path is not None:
            try:
                input_path.unlink(missing_ok=True)
            except OSError:
                pass
        engine.dispose()
    return True


def main() -> int:
    idle_sleep = float(os.environ.get("MOBIUS_WORKER_IDLE_SLEEP", "1.0"))
    once = os.environ.get("MOBIUS_WORKER_ONCE", "0") == "1"
    while True:
        worked = run_once()
        if once:
            return 0
        if not worked:
            time.sleep(max(0.1, min(idle_sleep, 30.0)))


if __name__ == "__main__":
    raise SystemExit(main())
