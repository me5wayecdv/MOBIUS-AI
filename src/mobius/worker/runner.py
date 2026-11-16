"""Queue consumer for isolated manifest and DEX analysis workers.

The worker reads content-addressed APK objects and updates worker_jobs only. It never
queries investigations, users, authorizations, findings, evidence, or event tables.
"""
from __future__ import annotations

import os
import socket
import time
from pathlib import Path

from pydantic import BaseModel, ConfigDict

from ..adapters.db import make_engine, make_session_factory
from ..services.artifacts import ArtifactStore
from ..services.oci_backend import OciBackend
from ..services.tool_runner import ToolLimits, ToolRunner, ToolSpec
from ..services.worker_queue import WorkerQueue

_RECON_BINARY = "/usr/local/bin/mobius-recon-manifest"
_DEX_BINARY = "/usr/local/bin/mobius-dex-index"


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
    raise RuntimeError(f"unsupported worker job kind: {kind}")


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
        workspace_root.mkdir(parents=True, exist_ok=True)
        workspace = workspace_root / scan_id
        if workspace.is_symlink():
            raise RuntimeError("worker workspace must not be a symlink")
        workspace.mkdir(mode=0o700, parents=True, exist_ok=True)
        input_path = workspace / "input.apk"
        if input_path.exists() or input_path.is_symlink():
            input_path.unlink()
        input_path.write_bytes(payload)
        input_path.chmod(0o400)

        binary, image, spec = _tool_for(kind, runtime)
        backend = OciBackend(runtime=runtime, binary_images={binary: image})
        runner = ToolRunner(workspace_root=workspace_root, backend=backend, tools=(spec,))
        result = runner.invoke(investigation_id=scan_id, tool=spec.name, args={})
        if result.status != "ok" or result.exit_code != 0 or result.truncated:
            raise RuntimeError(
                f"isolated {kind} failed: {result.status}; output_truncated={result.truncated}; "
                f"{result.stderr_tail}"
            )

        if kind == "recon_manifest":
            value = result.stdout.decode("utf-8", errors="strict")
            if not value.startswith("<?xml") and "<manifest" not in value[:2048]:
                raise RuntimeError("isolated RECON returned no recognizable XML manifest")
            output = {"manifest_xml": value}
        elif kind == "dex_index":
            # Validate JSON syntax and size here; the API performs the full schema and
            # artifact-digest validation before accepting or applying the result.
            import json
            value = json.loads(result.stdout.decode("utf-8", errors="strict"))
            if not isinstance(value, dict) or value.get("schema_version") != 1:
                raise RuntimeError("isolated DEX worker returned an unsupported result schema")
            output = value
        else:  # defensive: _tool_for is the closed registry
            raise RuntimeError(f"unsupported worker job kind: {kind}")

        session = factory()
        try:
            WorkerQueue(session).succeed(job_id, worker_id, output)
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
