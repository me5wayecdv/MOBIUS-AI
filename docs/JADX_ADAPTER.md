# D-012 — JADX adapter and decompilation cache

**Status: engineering implementation complete; image publication pending owner decision.** The adapter is implemented behind the existing fail-closed
`ToolRunner` boundary. It does not invoke a process itself and cannot run unless the caller supplies
a registered JADX `ToolSpec` and a backend that reports verified isolation.

## Execution contract

- JADX is pinned by the server-side tool registration; the current target is **1.5.6**.
- The executable path and argv are server-owned. The input name is restricted to `input.apk` or
  `input.dex`; output is restricted to a generated per-version workspace directory.
- The registered limits are 300 seconds, 4 GiB memory, 300 CPU seconds, 1 MiB captured process output,
  and network disabled.
- Production execution must use the existing digest-pinned, networkless OCI backend. No API-process
  subprocess fallback is provided.
- The CI-only real-process smoke test uses the checked-in `tests/fixtures/dex/AnalysisTest.dex`
  fixture through a test-only backend. It does not run an uploaded APK, emulator, or device.

## Cache contract

Cache entries are stored at:

```text
<cache-root>/<artifact-sha256>/<jadx-version>/
  manifest.json
  sources/...
```

- A POSIX file lock serializes generation for the same digest/version key.
- Cache manifests record the artifact digest, JADX version, relative source paths, byte sizes and
  SHA-256 of every Java/smali source file.
- A cache hit is returned only after manifest identity and every referenced source file are checked.
  Corrupt entries fail explicitly; they are not silently overwritten or treated as cache misses.
- Source references are relative, traversal-safe, verified against the cache inventory, and limited
  to snippets of at most 40 lines.

## Explicit failure states

The adapter distinguishes invalid input/digest, unavailable tool or isolation backend, rejected
tool invocation, timeout/non-zero exit, invalid/empty output, output-budget exhaustion, workspace
conflict, I/O failure, and corrupt cache. No failed decompilation is represented as a successful
empty source result.

## D-013 worker integration and publication boundary

The queued worker integration and API registration are documented in
[`ISOLATED_JADX_WORKER.md`](ISOLATED_JADX_WORKER.md). The API enqueues a `jadx_decompile` job;
the worker uses the digest-pinned OCI backend and writes a verified digest/version cache shared with
the API. The API reads only verified cache entries.

The local-image CI workflow builds and loads `mobius-jadx:ci` on the runner with `push: false`,
then runs the real checked-in `AnalysisTest.dex` fixture through JADX 1.5.6 and verifies the
resulting cache and a second-call cache hit. This is a local runner test, not a publication.

GHCR publication is a separate `workflow_dispatch`-only workflow requiring an explicit approval
input and approval reference. It has not been run. The D-013 engineering work is complete on this
branch except for publication of the immutable image, which remains blocked pending the project
owner's decision and explicit approval. Until an approved digest is configured, the API refuses
to enqueue decompilation (503); no mutable tag or unsandboxed fallback is accepted.

No migration, production database change, deployment, GHCR push, paid service, or new Python
dependency is introduced by the local-only CI workflow.
