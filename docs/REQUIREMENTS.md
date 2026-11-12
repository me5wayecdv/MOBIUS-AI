# REQUIREMENTS

**Status:** Draft for approval
**ID scheme:** `FR-<area>-<n>` functional, `NFR-<area>-<n>` non-functional, `AC-<id>` acceptance criteria.
**Rule:** a requirement without an acceptance criterion does not exist.

---

## 1. Functional requirements

### 1.1 Intake & authorisation (`AUTH`)

| ID | Requirement |
|---|---|
| FR-AUTH-1 | Upload an APK (≤ 200 MB), compute SHA-256, reject duplicates by hash unless `force=true`. |
| FR-AUTH-2 | Store an `Authorization` record with authoriser, scope text, intensity 0–3, expiry, and statement; block investigation start without a valid matching record. |
| FR-AUTH-3 | Reject an APK whose SHA-256 does not match an existing authorisation. |
| FR-AUTH-4 | Support intensity downgrade at any time; intensity upgrade requires a new authorisation. |
| FR-AUTH-5 | Provide `EMERGENCY_STOP` that cancels all `RUNNING` investigations and revokes tool leases within 5 s. |

**AC-FR-AUTH-2:** starting an investigation with no authorisation returns `409 AUTH_REQUIRED` and creates a `decision` event recording the refusal.
**AC-FR-AUTH-5:** integration test asserts every in-flight investigation transitions to `CANCELLED` and no tool process survives (checked via process table).

### 1.2 Reconnaissance (`RECON`)

| ID | Requirement |
|---|---|
| FR-RECON-1 | Parse binary `AndroidManifest.xml` and extract package, versionCode/Name, min/targetSdk, `debuggable`, `allowBackup`, `usesCleartextTraffic`, `networkSecurityConfig`. |
| FR-RECON-2 | Enumerate activities, services, receivers, providers with `exported` (explicit or intent-filter-implied), `permission`, and intent filters (actions, categories, schemes, hosts). |
| FR-RECON-3 | Enumerate requested and declared permissions with protection level where obtainable. |
| FR-RECON-4 | Extract signing certificate (subject, issuer, validity, SHA-256), detect v1-only/v2/v3 schemes, flag `debug`-signed and past-expiry certs. |
| FR-RECON-5 | Inventory DEX files (count, sizes), native libs per ABI, `assets/` notable files, and `res/raw/`. |
| FR-RECON-6 | Parse `res/xml/network_security_config.xml`: cleartext policy, trust anchors, `<debug-overrides>`, pin sets. |
| FR-RECON-7 | Every extracted fact carries a `source_ref` (file path + line/offset) so the UI can show provenance. |

**AC-FR-RECON-2:** on the DIVA APK, the exported-component set matches the published reference list (precision ≥ 0.9, recall ≥ 0.9); mismatches are enumerated in the test report.
**AC-FR-RECON-7:** schema validation fails if any `Observation` of type `fact` lacks `evidence_refs`.

### 1.3 Code investigation (`CODE`)

| ID | Requirement |
|---|---|
| FR-CODE-1 | Decompile on demand with JADX into a per-investigation cache keyed by APK hash; never decompile the same APK twice. |
| FR-CODE-2 | Provide targeted lookup primitives: find class, find method, find references to API set, find string, find callers of a method. |
| FR-CODE-3 | Support smali-level fallback when JADX fails on a method, and mark the observation's `fidelity` as `smali` or `decompiler-failed`. |
| FR-CODE-4 | Every code observation includes file, class, method, line range, and a quoted snippet ≤ 40 lines. |
| FR-CODE-5 | Sensitive-API catalogue is data-driven (YAML), versioned, and mapped to MASWE IDs. |

**AC-FR-CODE-3:** a synthetic APK with a deliberately un-decompilable method produces an observation with `fidelity="decompiler-failed"` and the pipeline continues (no crash).
**AC-FR-CODE-5:** adding a new rule to the YAML requires no code change; covered by a test that loads a fixture catalogue.

### 1.4 Adaptive investigation (`NEXUS`)

| ID | Requirement |
|---|---|
| FR-NEXUS-1 | Maintain an investigation worklist ("frontier") of candidate actions, each with a score, cost, and required agent. |
| FR-NEXUS-2 | Select the next action from a **closed registry** of validated actions; reject any action not in the registry. |
| FR-NEXUS-3 | Record a `Decision` for every selection: observation considered, evidence refs, alternatives rejected, expected outcome, remaining uncertainty. |
| FR-NEXUS-4 | Enforce step, wall-clock, and tool-call budgets; on exhaustion set `BUDGET_EXHAUSTED` and emit a partial report. |
| FR-NEXUS-5 | Terminate a hypothesis branch after N consecutive non-informative actions (default 3) rather than looping. |
| FR-NEXUS-6 | Re-plan when a new observation contradicts an assumption used by a prior decision; record the superseding decision. |
| FR-NEXUS-7 | Support pause/resume mid-investigation with state fully persisted (no in-memory-only state). |

**AC-FR-NEXUS-2:** an LLM proposal naming a non-registry action is rejected, logged as `planner_rejected`, and the next-best registry action is used. Test injects a poisoned proposal.
**AC-FR-NEXUS-5:** a loop-detection unit test with a stub agent scoring constant-information observations terminates within the configured bound.
**AC-FR-NEXUS-7:** kill the worker process mid-investigation; resume reconstructs identical state and continues without duplicating completed actions.

### 1.5 Validation (`VERITAS`)

| ID | Requirement |
|---|---|
| FR-VER-1 | No finding may reach status `CONFIRMED` without satisfying the confirmation gate for its vulnerability class. |
| FR-VER-2 | VERITAS is invoked with a role that did not produce the finding; the producing agent's rationale is *not* passed as authoritative. |
| FR-VER-3 | Verdicts are one of `CONFIRMED`, `REJECTED`, `NEEDS_MANUAL_REVIEW`, `INSUFFICIENT_EVIDENCE` — no binary forcing. |
| FR-VER-4 | Rejection requires a stated reason category (e.g. `not-reachable`, `sanitised`, `mitigated-by-platform`, `misread-code`). |
| FR-VER-5 | A `REJECTED` finding remains visible with its history; it is never deleted. |

**AC-FR-VER-1:** a parameterised test asserts every class in the gate table rejects a finding that omits the required evidence types.
**AC-FR-VER-4:** schema requires `rejection_reason` non-null when verdict is `REJECTED`.

### 1.6 Evidence (`EV`)

| ID | Requirement |
|---|---|
| FR-EV-1 | Evidence is content-addressed (SHA-256) and immutable after write. |
| FR-EV-2 | Evidence types: `manifest`, `source`, `smali`, `dex-string`, `tool-output`, `http`, `logcat`, `config`, `certificate`, `screenshot`. |
| FR-EV-3 | An automated referential-integrity check fails CI if any `evidence_refs` entry is dangling. |
| FR-EV-4 | Evidence has a retention policy; tool-output blobs over a threshold are gzipped and may be pruned while the hash and summary remain. |

**AC-FR-EV-3:** CI job `audit-evidence-refs` runs against the seeded corpus and exits non-zero on a dangling ref.

### 1.7 Attack graph (`GRAPH`)

| ID | Requirement |
|---|---|
| FR-GRAPH-1 | Nodes and edges carry `assertion` ∈ {`observed`, `hypothesis`, `confirmed`, `rejected`}. |
| FR-GRAPH-2 | Hypothetical edges are returned by API but flagged, and are visually distinct in the UI. |
| FR-GRAPH-3 | Graph API supports bounded expansion (node neighbourhood, depth ≤ 3) — never a full dump. |
| FR-GRAPH-4 | Path query between two nodes returns only edges satisfying a caller-specified minimum assertion level. |

**AC-FR-GRAPH-2:** API test asserts every edge with `assertion="hypothesis"` also has non-empty `rationale`.
**AC-FR-GRAPH-3:** a request for depth > 3 is clamped, with a `truncated` flag in the response.

### 1.8 Real-time console (`WAR`)

| ID | Requirement |
|---|---|
| FR-WAR-1 | Stream events over `/ws/scans/{id}` with monotonic `seq` per scan; client detects gaps. |
| FR-WAR-2 | On reconnect, client requests events after last seen `seq` and receives the missed range. |
| FR-WAR-3 | Agent status is derived from events, never set by the client. |
| FR-WAR-4 | Idle scan renders an idle state; no placeholder or synthesised activity. |
| FR-WAR-5 | Code viewer shows real decompiled output with server-provided highlight ranges. |

**AC-FR-WAR-2:** killed socket during a running scan; on reconnect the client's event log equals the server's (order and content). Verified by a test harness that diffs both logs.
**AC-FR-WAR-4:** with a `DRAFT` scan, a Playwright assertion confirms zero feed rows and an explicit empty state.

### 1.9 Reporting (`RPT`)

| ID | Requirement |
|---|---|
| FR-RPT-1 | Generate a report with: scope, method, findings table, per-finding evidence, confidence, MASVS/MASWE mapping, reproduction, remediation, and an "unknowns" section. |
| FR-RPT-2 | Report states investigation completeness (actions taken vs. frontier abandoned at budget exhaustion). |
| FR-RPT-3 | Reports are versioned; regenerating does not mutate a prior report. |

**AC-FR-RPT-2:** a budget-exhausted investigation's report contains a non-empty "What we did not determine" section listing abandoned frontier entries with scores.

---

## 2. Non-functional requirements

| ID | Requirement | Verification |
|---|---|---|
| NFR-PERF-1 | UI event latency (tool completion → rendered) p95 < 500 ms on localhost | Instrumented timing in the E2E harness |
| NFR-PERF-2 | RECON of a 50 MB APK completes < 60 s | Benchmark fixture |
| NFR-PERF-3 | Graph endpoint responds < 800 ms for a 500-node neighbourhood | Seeded graph benchmark |
| NFR-SEC-1 | All tool execution via argv arrays; no `shell=True` anywhere | `ruff` rule + grep gate in CI |
| NFR-SEC-2 | Analysis of untrusted APKs occurs in a worker with no write access to the DB and no outbound network by default | Compose network policy + test |
| NFR-SEC-3 | Uploaded files are never executed by the API process | Architecture test: API has no `subprocess` import |
| NFR-SEC-4 | Secrets via environment only; `.env` git-ignored; startup fails if a required secret is default | Startup check + test |
| NFR-REL-1 | An agent or tool failure never aborts the investigation; it produces an `agent_error` event and frontier adaptation | Fault-injection test suite |
| NFR-REL-2 | All state survives process restart | Restart test |
| NFR-AUD-1 | Every state transition is an appended event; there are no silent mutations | Review + event-coverage test |
| NFR-COST-1 | Per-investigation LLM token budget enforced in code; breach stops the scan | Budget test with a stub model |
| NFR-PORT-1 | Tool adapters resolvable by config path; absence of a tool degrades gracefully with `tool_unavailable` | Run with JADX absent |
| NFR-DATA-1 | APK artefacts stored outside the repo; DB stores hash + metadata + object key | Review of storage layout |

---

## 3. Requirement-to-value audit (the anti-bloat check)

The master prompt asks to challenge its own scope. Here is what the requirements above deliberately
**do not** include, and why:

| Proposed in master prompt | Decision | Rationale |
|---|---|---|
| 14 distinct screens | **Cut to 5** for v1 | Screens are cheap to draw and expensive to fill with real data. Five fully-data-driven screens beat fourteen mocked ones. |
| ORACLE module | **Deferred** | Not on the critical path to "credible investigation"; optional by its own definition. Defensive analysis is documented, not built. |
| Redis | **Deferred** | Postgres `LISTEN/NOTIFY` + durable event table meets the requirement with one less service (ADR-007). |
| Graph database | **Rejected** | Adjacency tables + recursive CTE suffice at expected scale (ADR-006). |
| Per-agent model routing | **Simplified to 2 tiers** | Evaluating 8 agents × N models is not feasible in the time available (ADR-010). |
| Provider-independent abstraction with plugin registry | **Reduced to one interface, two impls** | Build the abstraction; only prove two providers. |
| Full MASVS/RESILIENCE testing including anti-tampering bypass | **Descoped to detection, not bypass** | Patching/repackaging targets is a different project and raises ethics questions. |
