# MOBIUS Main-Branch Architecture & Security Audit

**Audit date:** 2026-11-15  
**Audited ref:** `main`  
**Audited commit:** `c8e612ad183879f1425a2557de51a26981e26913`  
**Method:** repository tree, architecture/requirements/implementation documents, API routes, dependency wiring, intake, artifact/evidence storage, event store, NEXUS, RECON, SPECTRE, gates, ORM models, migrations, tests and CI workflow.  
**Scope note:** this is a source-level review. It is not a penetration test, runtime deployment test, APK fuzzing exercise, or independent Android security assessment.

---

## 1. Executive assessment

MOBIUS has a meaningful backend foundation: domain schemas and gates, APK intake, authorization records, manifest parsing, a bounded DEX call-graph analysis path, durable evidence, event replay, report generation, migrations, and a CI matrix that now exercises Python 3.11/3.12 with PostgreSQL 16.

It is **not yet a secure multi-user analysis platform and must not be exposed as a production service**. The largest blockers are not missing screens. They are the trust boundary around an untrusted APK, the absence of real identity and per-user authorization, and the absence of a sandboxed analysis worker.

The current implementation is best described as:

> A development-only, single-process, evidence-oriented Android static-analysis prototype with a deterministic manifest/DEX pipeline and a bounded dispatcher. It is not yet an autonomous multi-agent platform, dynamic-analysis system, or production security service.

No architecture reduction is approved by this audit. PHANTOM, VECTOR, model-backed reasoning, independent VERITAS, and the broader MOBIUS vision remain future scope unless the Project Director explicitly changes it.

## 2. Findings (prioritized)

### F-01 — Stub identity is not authentication; there is no tenant boundary

**Severity:** Critical before any shared or network-accessible deployment  
**Evidence:** `src/mobius/api/deps.py`, `src/mobius/api/routes.py`, `src/mobius/services/intake.py`

- `analyst_id` trusts the caller-supplied `X-Analyst-Id` header or a default value.
- There is no JWT/session verification or authenticated principal.
- Several read endpoints (scan listing/details, events, findings, evidence, reports and application reads) do not establish ownership of the requested resource.
- `list_scans` queries investigations globally rather than filtering by owner.
- `IntakeService._ensure_user` creates placeholder users from supplied identifiers.
- Startup now refuses environment names other than development/dev/test, which is useful fail-closed configuration, but the environment variable is not an authentication mechanism. A deployment misconfigured as `test` or `dev` can still start with stub identity.

**Impact:** callers can impersonate another analyst by changing a header and potentially read or mutate other investigations. Current restrictions reduce the intended deployment scope but do not provide tenant isolation.

**Required remediation:**
1. Implement a verified principal (JWT/OIDC or a documented local identity provider); never trust an identity header as proof.
2. Introduce explicit ownership/tenant checks for every application, authorization, scan, event, finding, evidence, and report operation.
3. Make list endpoints tenant-scoped by construction.
4. Remove placeholder-user creation from production paths.
5. Add cross-user negative tests for every resource route and fail startup unless real auth is configured outside an explicitly isolated local mode.

### F-02 — Untrusted APK parsing occurs in the API process; no analysis sandbox exists

**Severity:** Critical before accepting untrusted uploads  
**Evidence:** `src/mobius/api/routes.py`, `src/mobius/services/recon.py`, `src/mobius/services/spectre.py`, `src/mobius/api/deps.py`, `docs/REQUIREMENTS.md`

- RECON extracts and parses the binary manifest through androguard in the application process.
- SPECTRE indexes DEX in the application process.
- Health reports `sandbox: process (container runtime not detected)`.
- The Tool Runner sandbox is explicitly `NOT STARTED` in `docs/IMPLEMENTATION_STATUS.md`.
- No isolated worker boundary, per-job filesystem, CPU/memory/time limits, network-deny policy, or credential separation is implemented.

**Impact:** parser vulnerabilities, pathological archives, or resource-exhaustion inputs affect the API process and its database/artifact access. The design requirement NFR-SEC-2 is not met.

**Required remediation:**
1. Keep the API limited to bounded intake, authorization, and job submission.
2. Run all APK parsing/indexing in an unprivileged worker/container with no database credentials and no outbound network by default.
3. Mount only the single job's input read-only and its output directory write-limited.
4. Enforce CPU, memory, process-count, disk, and wall-clock quotas outside the worker's control.
5. Treat missing container runtime as a hard capability failure for untrusted analysis, not as a warning.
6. Add malicious/oversized archive and worker-kill integration tests.

### F-03 — Upload size is bounded only after multipart parsing

**Severity:** High  
**Evidence:** `src/mobius/api/routes.py::upload_application`

The route reads at most `MAX_APK_BYTES + 1`, which prevents an unbounded in-memory read in the handler. However, FastAPI/Starlette must parse and spool the multipart request before the route receives its `UploadFile`. There is no demonstrated request-body limit at the reverse proxy/server/multipart parser boundary.

**Impact:** a client can still send a request far larger than 200 MB and consume temporary disk, network bandwidth, and multipart parsing resources before the handler rejects it.

**Required remediation:** enforce a request-body cap at the ingress/server layer; configure multipart limits; use a streaming upload path with byte counting; enforce entry-count, compressed/uncompressed-size and compression-ratio limits before archive processing; test oversized multipart bodies at the HTTP boundary.

### F-04 — Authorization target package is not proven against the APK package

**Severity:** High  
**Evidence:** `src/mobius/services/intake.py::create_authorization`, `create_investigation`, `src/mobius/services/recon.py`

Authorization is bound to the APK SHA-256, which is valuable. However, `target_package` is accepted as supplied and the investigation creation path checks the APK hash but does not compare the authorization's target package to the package parsed from that APK. Package metadata is populated later by RECON.

**Impact:** the authorization record can claim a different package identity from the actual uploaded APK. The hash binding still identifies the exact bytes, but the scope record is internally inconsistent and may mislead an operator.

**Required remediation:** parse and persist package identity during intake using a bounded, isolated parser, or require RECON to verify package equality before any analysis action. Refuse mismatches and persist the refusal as an auditable decision/event.

### F-05 — Duplicate upload contract does not match the API specification

**Severity:** Medium  
**Evidence:** `src/mobius/api/routes.py::upload_application`, `docs/API_SPECIFICATION.md §2`

The API specification describes duplicate upload as `409 APK_DUPLICATE` unless `force=true`. The route currently returns HTTP 201 with a `duplicate: true` body when the same SHA-256 already exists and `force=false`. The `force` flag does not currently create a new copy; the store and application table are content-addressed/unique by hash.

**Impact:** clients cannot rely on the published stable error contract, and the meaning of `force` is ambiguous.

**Required remediation:** choose and document one contract. Prefer 409 with the existing application reference when `force=false`; define `force=true` as reusing the existing immutable artifact while explicitly creating a new investigation only if that is the intended behavior. Do not imply that force duplicates the content-addressed artifact.

### F-06 — Current SPECTRE result is reachability, not taint or exploitability

**Severity:** High for claims about vulnerability confirmation  
**Evidence:** `src/mobius/services/spectre.py`, `src/mobius/core/reachability.py`, `docs/IMPLEMENTATION_STATUS.md`, ADR-022

- The current indexer is single-DEX and the implementation has no data-flow/taint analysis or CFG.
- It does not cover multidex, reflection, obfuscated dynamic dispatch, or framework call paths.
- A same-method guard is treated conservatively without instruction-order analysis.
- The implementation status records no confirmed true positive on real code.

**Impact:** a call path to a sink is not proof that attacker-controlled data reaches the sink or that the path is executable. A complete negative search is only a negative result within the supported model, not proof of safety.

**Required remediation:** preserve current abstention semantics; add multidex and provenance-aware indexing; add CFG and data-flow/taint tracking; validate against independently labelled positive and negative APKs; keep the limitations visible in findings and reports.

### F-07 — NEXUS is a deterministic dispatcher, not an adaptive planner

**Severity:** Medium (product capability/positioning)  
**Evidence:** `src/mobius/services/nexus.py`, ADR-023, `docs/IMPLEMENTATION_STATUS.md`

NEXUS dispatches work already present in the frontier using a deterministic score. It cannot invent new investigative hypotheses or re-plan from observations. Entries for unavailable agents are recorded as dropped/deferred rather than executed.

**Impact:** calling the current implementation an autonomous multi-agent investigator would overstate its capabilities.

**Required remediation:** retain the honest dispatcher label until a model-backed planner exists. When implemented, constrain proposed actions to a typed, allowlisted registry, validate scope/budget before execution, record alternatives and rationale, and test poisoned/invalid planner proposals.

### F-08 — VERITAS model agent and independent model review do not exist

**Severity:** High for validation claims  
**Evidence:** `src/mobius/services/validation.py`, `docs/IMPLEMENTATION_STATUS.md`, ADR-010

Deterministic confirmation gates and validator identity checks exist, but the independent model-backed VERITAS agent does not. A different string in `validated_by` is not by itself evidence that a genuinely independent reviewer/model evaluated the claim.

**Impact:** the system can validate gate attributes, but cannot claim independent model-based adversarial review.

**Required remediation:** implement a provider abstraction and explicit reviewer execution record; enforce reviewer/model separation at runtime; store the review input/output and model/version; ensure the reviewer does not receive the producer's rationale as authoritative; preserve the deterministic gate as final authority.

### F-09 — PHANTOM, VECTOR, graph persistence/UI, and a production frontend remain absent

**Severity:** Medium/High depending on product claims  
**Evidence:** `docs/IMPLEMENTATION_STATUS.md`, repository tree

- PHANTOM/emulator analysis: not started.
- VECTOR/network/API analysis: not started.
- Attack graph persistence tables and graph UI: not implemented.
- The current War Room is a static HTML page; no full product frontend/browser E2E coverage is recorded.
- ORACLE is deliberately out of v1 scope; that does not remove the broader defensive threat-intelligence concept from the long-term vision.

**Impact:** the current slice is static analysis only and should not be presented as the full platform.

**Required remediation:** keep the missing agents and interfaces visible in the roadmap; add each capability behind a typed port and only show activity supported by persisted events.

### F-10 — Documentation has drifted from the current main branch

**Severity:** Medium  
**Evidence:** `docs/CURRENT_REPOSITORY_STATE.md`, `docs/IMPLEMENTATION_STATUS.md`, PR #11

- `CURRENT_REPOSITORY_STATE.md` still contains an older snapshot and contradictory statements such as the absence of source code, despite its superseded note.
- `IMPLEMENTATION_STATUS.md` has an earlier base commit/branch reference and says PostgreSQL trigger tests were skipped/never executed, while PR #11's CI now runs PostgreSQL 16 integration tests.
- The event component row refers to a LISTEN/NOTIFY bridge, while ADR-021 and the implementation use SSE polling of the event table.

**Impact:** project decisions and capability claims can be made from stale facts.

**Required remediation:** regenerate the repository snapshot on each milestone; keep implementation status tied to a verified commit; distinguish designed, partial, and tested capabilities.

---

## 3. What is genuinely implemented on main

The following are supported by code and tests/CI, with the limitations above:

- FastAPI application and API routes for applications, authorizations, investigations, events, findings, evidence, validation, RECON, SPECTRE, NEXUS, and reports.
- Domain schemas, investigation state machine, deterministic confirmation gates, and bounded frontier scoring.
- APK ZIP intake with SHA-256 identity and content-addressed local artifact storage.
- Binary Android manifest parsing through androguard.
- DEX indexing and bounded application-level call-graph reachability for the supported single-DEX path.
- Evidence metadata and immutable content-addressed artifact writes at the service level.
- Per-investigation append-only event rows, SSE replay/resume by sequence.
- Markdown report generation from stored rows.
- Alembic migration history and PostgreSQL authorization-trigger integration coverage in CI.
- GitHub Actions matrix for Python 3.11 and 3.12 with PostgreSQL 16 and SQLite migration smoke test.

## 4. Recommended next vertical slice

Do **not** build another dashboard or add more agent names next. Build the isolated analysis execution boundary first. This unlocks safe parser execution and is a prerequisite for JADX, Apktool, PHANTOM and future VECTOR tooling.

### Slice: Isolated Analysis Job Runtime

**Goal:** API intake creates an authorized, bounded analysis job; an isolated worker processes one APK and returns typed, content-addressed outputs. No worker has API/database credentials or network access.

**Implementation order:**

1. Define typed job contract: job ID, investigation ID, APK digest, authorization snapshot, permitted action set, intensity, budgets, input artifact digest, output manifest.
2. Add durable job state and event transitions: queued → leased → running → succeeded/failed/cancelled/timed_out. Persist lease owner, expiry, heartbeat, attempts and stop reason.
3. Add a worker adapter interface and a local container-backed implementation. Do not execute analyzers in FastAPI request handlers.
4. Enforce a container profile: non-root UID, read-only root filesystem, no network, no host mounts except per-job read-only input and bounded output, dropped capabilities, seccomp/AppArmor where available, CPU/memory/PID/disk/time limits.
5. Add a worker supervisor that kills the entire process/container on timeout, cancellation, or lease expiry.
6. Worker emits a signed/validated output manifest; API verifies output file paths, size, SHA-256, job ID, input digest, tool versions and declared evidence types before importing evidence.
7. Move manifest and DEX parsing into this worker as the first two actions. Keep the existing services as orchestration/domain services, not subprocess owners.
8. Add adversarial integration tests: path traversal output, symlink escape, oversized output, malformed ZIP/AXML/DEX, worker crash, timeout, cancellation, network egress attempt, and stale lease recovery.
9. Update health/readiness so analysis capability is unavailable when the sandbox runtime/profile is unavailable. No silent process-mode fallback for untrusted APKs.

**Acceptance criteria:**
- No APK parsing/indexing occurs in the API process.
- Worker has no database credentials and cannot reach the network.
- API refuses to launch analysis if isolation cannot be established.
- Cancellation and timeout kill the worker and leave an auditable terminal job state.
- Output import accepts only files listed in a verified manifest and checks their digest/size.
- All state and events survive API/worker restarts.
- CI tests the job state machine and contract; a dedicated runner tests real container isolation.

### Following slices (in order)

1. Real authentication + tenant isolation (must precede any shared deployment; can be developed in parallel with the worker boundary).
2. Hardened APK intake and archive resource limits.
3. Isolated RECON/SPECTRE worker migration.
4. Multi-DEX, CFG and taint/data-flow analysis.
5. Provider abstraction + model benchmark + model-backed SPECTRE hypotheses.
6. Independent VERITAS reviewer with separate model execution.
7. PHANTOM on a controlled emulator/physical lab and VECTOR in an authorized network lab.
8. Attack graph persistence/API/UI and full War Room browser tests.

## 5. Release decision

**Decision: NO-GO for production or internet exposure. GO for continued isolated development and controlled test APKs only.**

The existing CI pass proves the tested Python matrix and PostgreSQL/SQLite paths, not sandbox isolation, authentication, tenant security, Android analysis accuracy, or production readiness.

## 6. Audit limitations

This review did not execute the application, run a container escape test, fuzz APK parsers, test real JWT/OIDC flows, or validate findings against an independently labelled corpus. Those remain explicit future verification tasks.
