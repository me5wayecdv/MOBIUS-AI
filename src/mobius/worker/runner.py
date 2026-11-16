"""Queue consumer for the isolated RECON manifest worker.

The worker has two capabilities only: read content-addressed APK objects and update
worker_jobs. It does not query investigations, users, authorizations, findings or events.
"""
from __future__ import annotations

import os
import socket
import time
from pathlib import Path
from typing import Type

from pydantic import BaseModel, ConfigDict
from sqlalchemy.orm import Session

from ..adapters.db import make_engine, make_session_factory
from ..services.artifacts import ArtifactStore
from ..services.oci_backend import OciBackend
from ..services.tool_runner import ToolLimits, ToolRunner, ToolSpec, ToolUnavailable
from ..services.worker_queue import WorkerQueue

_BINARY = "/usr/local/bin/mobius-recon-manifest"


class ReconArgs(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


def _required(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise RuntimeError(f"{name} must be configured")
    return value


def run_once() -> bool:
    db_url = _required("MOBIUS_WORKER_DB_URL")
    artifact_root = Path(_required("MOBIUS_ARTIFACT_ROOT")).resolve()
    workspace_root = Path(_required("MOBIUS_WORKSPACE_ROOT")).resolve()
    runtime = _required("MOBIUS_OCI_RUNTIME")
    image = _required("MOBIUS_RECON_IMAGE")
    worker_id = os.environ.get("MOBIUS_WORKER_ID") or f"{socket.gethostname()}-{os.getpid()}"

    engine = make_engine(db_url)
    factory = make_session_factory(engine)
    claim_session = factory()
    try:
        job = WorkerQueue(claim_session).claim(worker_id)
        if job is None:
            claim_session.rollback()
            return False
        job_id, scan_id, artifact_key = job.id, job.investigation_id, job.artifact_key
        claim_session.commit()
    except Exception:
        claim_session.rollback()
        raise
    finally:
        claim_session.close()

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

        backend = OciBackend(runtime=runtime, binary_images={_BINARY: image})
        spec = ToolSpec(
            name="recon_manifest",
            binary=_BINARY,
            version="mobius-recon-manifest-v1",
            args_model=ReconArgs,
            build_argv=lambda _args: (_BINARY, "--input", "/work/input.apk"),
            limits=ToolLimits(
                timeout_seconds=90,
                memory_mb=768,
                cpu_seconds=60,
                max_output_bytes=12 * 1024 * 1024,
                network_enabled=False,
            ),
        )
        runner = ToolRunner(workspace_root=workspace_root, backend=backend, tools=(spec,))
        result = runner.invoke(investigation_id=scan_id, tool="recon_manifest", args={})
        if result.status != "ok" or result.exit_code != 0:
            raise RuntimeError(f"isolated RECON failed: {result.status}; {result.stderr_tail}")
        manifest_xml = result.stdout.decode("utf-8", errors="strict")
        if not manifest_xml.startswith("<?xml") and "<manifest" not in manifest_xml[:2048]:
            raise RuntimeError("isolated RECON returned no recognizable XML manifest")
        session = factory()
        try:
            WorkerQueue(session).succeed(job_id, worker_id, {"manifest_xml": manifest_xml})
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
        try:
            input_path.unlink(missing_ok=True)
        except (UnboundLocalError, OSError):
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
