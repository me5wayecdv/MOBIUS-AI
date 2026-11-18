"""CI-only in-container smoke: real JADX -> digest/version cache -> verified cache hit.

This direct process backend is deliberately confined to the smoke container. Production execution
continues to use ToolRunner + the host-side digest-pinned OciBackend.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import time
from pathlib import Path

from mobius.adapters.jadx import JadxAdapter, build_jadx_tool_spec
from mobius.services.tool_runner import BackendResult, ToolRunner

SCAN_ID = "scn_01J8Z5K9WQ7R3T2M6N4P8V0ABC"
JADX_BINARY = "/opt/jadx/bin/jadx"


class InContainerSmokeBackend:
    """Runs the real binary inside the outer, networkless smoke container only."""

    isolation_ready = True

    def execute(self, *, argv, workspace, limits):
        command = [
            str(workspace / part.removeprefix("/work/")) if part.startswith("/work/") else part
            for part in argv
        ]
        started = time.monotonic()
        try:
            result = subprocess.run(
                command,
                cwd=workspace,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=limits.timeout_seconds,
                check=False,
                shell=False,
                env={
                    "PATH": "/opt/jadx/bin:/usr/lib/jvm/java-17-openjdk-amd64/bin:/usr/local/bin:/usr/bin:/bin",
                    "JAVA_HOME": "/usr/lib/jvm/java-17-openjdk-amd64",
                    "HOME": "/work/home",
                    "TMPDIR": "/tmp",
                },
            )
        except subprocess.TimeoutExpired as exc:
            return BackendResult(
                "timeout", None, exc.stdout or b"", exc.stderr or b"",
                int((time.monotonic() - started) * 1000),
            )
        diagnostic = result.stderr
        if result.returncode != 0:
            diagnostic = diagnostic + b"\\n[stdout]\\n" + result.stdout
            print("JADX command:", command, file=__import__("sys").stderr)
            print(diagnostic.decode("utf-8", errors="replace"), file=__import__("sys").stderr)
        return BackendResult(
            "ok" if result.returncode == 0 else "error",
            result.returncode,
            result.stdout,
            diagnostic,
            int((time.monotonic() - started) * 1000),
        )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--fixture", type=Path, required=True)
    parser.add_argument("--workspace-root", type=Path, required=True)
    parser.add_argument("--cache-root", type=Path, required=True)
    parser.add_argument("--result", type=Path, required=True)
    args = parser.parse_args()

    artifact = args.fixture.read_bytes()
    if not artifact:
        raise SystemExit("AnalysisTest.dex fixture is empty")
    digest = hashlib.sha256(artifact).hexdigest()
    if not Path(JADX_BINARY).is_file():
        raise SystemExit("pinned JADX binary is missing from image")
    version = subprocess.run(
        [JADX_BINARY, "--version"], check=True, capture_output=True, text=True,
        timeout=15, shell=False,
    ).stdout.strip()
    if version != "1.5.6":
        raise SystemExit(f"unexpected JADX version: {version!r}")

    runner = ToolRunner(
        workspace_root=args.workspace_root,
        backend=InContainerSmokeBackend(),
        tools=(build_jadx_tool_spec(binary=JADX_BINARY, version=version),),
    )
    adapter = JadxAdapter(runner=runner, cache_root=args.cache_root, tool_version=version)
    first = adapter.decompile(
        investigation_id=SCAN_ID,
        artifact=artifact,
        expected_sha256=digest,
        artifact_name="input.dex",
    )
    if first.cached or not first.source_files:
        raise SystemExit("real JADX invocation did not produce a fresh source cache")
    if not any(path.endswith((".java", ".smali")) for path in first.source_files):
        raise SystemExit("cache contains no decompiled Java/smali source")

    second = adapter.decompile(
        investigation_id=SCAN_ID,
        artifact=artifact,
        expected_sha256=digest,
        artifact_name="input.dex",
    )
    if not second.cached or second.cache_dir != first.cache_dir:
        raise SystemExit("second invocation did not reuse the verified digest/version cache")

    sample_path = first.source_files[0]
    snippet = adapter.resolve_source(
        first, relative_path=sample_path, start_line=1, end_line=1,
    )
    manifest_path = first.cache_dir.parent / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if manifest.get("apk_sha256") != digest or manifest.get("tool_version") != version:
        raise SystemExit("cache manifest identity does not match the DEX/JADX inputs")
    if len(manifest.get("source_files", [])) != len(first.source_files):
        raise SystemExit("cache manifest source inventory does not match the adapter result")

    result = {
        "status": "passed",
        "jadx_version": version,
        "dex_sha256": digest,
        "first_run_cached": first.cached,
        "second_run_cached": second.cached,
        "source_file_count": len(first.source_files),
        "sample_source": sample_path,
        "sample_line": snippet.text,
        "cache_manifest": str(manifest_path),
    }
    args.result.parent.mkdir(parents=True, exist_ok=True)
    args.result.write_text(json.dumps(result, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
