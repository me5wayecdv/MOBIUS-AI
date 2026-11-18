# D-012 — JADX adapter and decompilation cache

**Status: implementation in progress.** The adapter is implemented behind the existing fail-closed
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

## Remaining integration

D-013 owns class/method/source lookup APIs and War Room navigation. Wiring a configured, digest-pinned
JADX OCI image into the isolated worker/runtime and connecting decompiled references to persisted
CodeObservation/Evidence records remain follow-up integration work; this PR does not claim either is
operational. No migration, production database change, deploy, publication, paid service, or new
Python dependency is introduced.
