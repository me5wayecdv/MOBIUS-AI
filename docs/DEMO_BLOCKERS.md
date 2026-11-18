# Demo definition-of-done: critical path and owner decisions

**Status date:** 2026-11-18  
**Rule:** A green CI job proves code/test behavior, not APK exploitability, visual acceptance, or runtime capability. Do not mark a demo gate complete without its stated evidence.

## Owner decisions / environment required once

### D-001 — Pin the final intentionally vulnerable APK
Provide one APK owned by the project team and its source repository/commit. Record:
- APK file and SHA-256
- application package and version
- source repository and immutable commit/tag
- confirmation that the team is authorized to test this exact APK

Without this, JADX/source lookup, real code paths, coverage, and a real positive/negative PoC cannot be validated. The synthetic APK used by browser CI is explicitly not a substitute.

### D-002 — Freeze 2–3 demo scenarios
For each scenario, choose:
- entry point / source
- sensitive sink and expected security property
- required static evidence
- positive control and negative control
- whether runtime reproduction is required for the defence

The scenarios must be selected against the pinned APK, not invented from the synthetic CI fixture.

### D-003 — Confirm the actual demo host capabilities
Run the checks on the same machine/container host intended for the live defence and attach the output:
- JDK: `java -version`, `javac -version`
- JADX: `jadx --version` and confirm `/opt/jadx/bin/jadx` if using the prior Linux setup
- apktool: `apktool --version`
- Android SDK: `adb version`, `emulator -version`, SDK platform/build-tools availability
- emulator/KVM: `test -e /dev/kvm && ls -l /dev/kvm`
- Docker: `docker version`, `docker info`
- Ollama: `ollama list`, `ollama ps`, and a successful local inference using the chosen model

Historical environment notes are not current capability proof: a Linux host previously had JADX at `/opt/jadx/bin/jadx` and apktool 2.7.0; a Windows shell reported Oracle JDK 25.0.1, while a JDK 21 path was attempted but not verified. Android SDK, emulator/KVM and Docker availability have not been confirmed for the final demo host.

### D-020 / D-022 / D-026 — Real local model run
Provide:
- reachable Ollama base URL from the MOBIUS process
- exact model name/tag and `ollama show` metadata
- host where Ollama runs (same host, self-hosted runner, or other explicitly authorized local environment)
- confirmation that per-investigation model consent can be enabled for the demo fixture

GitHub-hosted CI cannot reach a developer's `localhost`; a real Ollama test needs a self-hosted runner or a local demo run on the same machine. Deterministic mock tests remain valid but do not satisfy the live-model acceptance criterion.

### D-004 — Freeze the defence scope and fallback
Confirm the one live investigation path and provide a recorded run of that same path as fallback. The recording must be labelled as recorded; it must never be blended into live events.

## Critical path, in order

1. **D-001 + D-002 + D-003 + D-004:** owner pins the APK, chooses scenarios, confirms host capabilities and freezes the live/fallback scope.
2. **D-010 + D-011:** run the multi-DEX worker path against the real APK; verify secondary DEX enumeration, digest binding, coverage and worker/image behavior. No deploy is included; only CI/local disposable-worker smoke tests.
3. **D-012 + D-013:** implement/verify JADX decompilation and cache by APK digest/tool version; expose class/method/source lookup so the UI can navigate to real code.
4. **D-014 + D-015 + D-016:** complete sensitive source/sink catalogue, bounded CFG/data-flow and coverage/limitations manifest for the selected scenarios.
5. **D-020 + D-022 + D-025 + D-026:** run real Ollama with explicit consent; validate structured hypotheses and adaptive investigation; broaden decision provenance/replay; wire VERITAS into the investigation/report path and measure model quality.
6. **D-021:** package actual decompiled source snippets, method/caller/sink/guard references and evidence IDs. This depends on D-012 and D-013; current manifest/observation evidence is not a replacement.
7. **D-030 + D-031 + D-032:** graph persistence, correlation and candidate-chain reasoning are implemented. **D-033:** visual proof is still pending owner review of the 1280px/390px screenshots.
8. **D-040–D-044:** typed PoC schema, allowlisted adapters, persisted PoC evidence, approval/timeout/cancel/cleanup and positive/negative integration tests are implemented. The current WebView harness is a simulation; replace/augment it with a reproducible PoC on the pinned APK and a verified local runtime if D-002/D-003 require runtime proof.
9. **D-050–D-055:** War Room panels are implemented in the active PR. Each panel needs a seeded-investigation screenshot at desktop 1280px and mobile 390px and human visual review. D-051 must remain empty when no real lifecycle events exist; D-053 must not claim source navigation until D-012/D-013 are complete.
10. **D-056:** browser E2E on the pinned APK must run upload → investigation → evidence → graph → real PoC → report; verify all visible states derive from persisted records/events and that the complete timeline sequence survives refresh. The current CI synthetic fixture only proves the UI/API/persistence contract.
11. **Final benchmark/report:** run the chosen positive/negative scenarios, record actual coverage and unsupported cases, produce reproducible evidence/report, and prepare the labelled fallback recording.

## Current implementation versus remaining acceptance

- D-030–D-032: implemented and backend-tested.
- D-033: React Flow implementation merged; visual acceptance pending.
- D-040–D-044: implemented and Python 3.11/3.12 + PostgreSQL CI-tested. D-043 approval is bound to the exact TestPlan digest (PR #49).
- D-050–D-055: UI implementation and screenshot workflow in progress; visual acceptance pending.
- D-056: browser E2E is running on a synthetic CI fixture. This is not yet the final APK/runtime demo.

## Explicitly out of scope unless the owner authorizes later

No deployment/publication, production database migration, data deletion/downgrade, key rotation, paid provider/service, or new dependency outside the approved plan. D-060 emulator runtime, D-061 network/API adapter, D-062 PDF export and D-063 broad catalogue remain optional/deferred until the critical path requires them.
