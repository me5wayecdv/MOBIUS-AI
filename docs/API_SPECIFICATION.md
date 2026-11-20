# API SPECIFICATION

**Status:** Proposed
**Base:** `/api/v1` · WebSocket `/ws/scans/{scan_id}`
**Contract source of truth:** generated OpenAPI 3.1 from FastAPI + Pydantic v2 models. This document
explains intent; the generated schema is normative. Any divergence is a bug.

---

## 1. Conventions

| Topic | Rule |
|---|---|
| IDs | ULID strings, prefixed by type: `app_`, `scn_`, `obs_`, `hyp_`, `dec_`, `fnd_`, `ev_`, `gph_` |
| Auth | `Authorization: Bearer <jwt>`; short-lived access token + refresh. CLI uses an API key. |
| Errors | RFC 9457 problem+json: `{type, title, status, detail, instance, code}` where `code` is a stable machine string |
| Pagination | Cursor-based: `?limit=50&after=<ulid>`. No offset — the event log is append-only. |
| Idempotency | `Idempotency-Key` header honoured on all `POST`s that create resources |
| Versioning | URL major version; additive changes only within v1 |
| Timestamps | ISO-8601 UTC with `Z` |
| Content types | `application/json`; APK upload is `multipart/form-data`; report download is `application/pdf` or `text/markdown` |
| Rate limits | upload 10/min/user; scan start 5/min/user; reads 600/min/user |

## 2. Stable error codes

| `code` | HTTP | Meaning |
|---|---|---|
| `AUTH_REQUIRED` | 409 | No valid authorisation for this APK hash (FR-AUTH-2) |
| `AUTH_EXPIRED` | 409 | Authorisation expired |
| `INTENSITY_NOT_GRANTED` | 409 | Requested intensity exceeds grant |
| `APK_TOO_LARGE` | 413 | > 200 MB |
| `APK_INVALID` | 422 | Not a ZIP / no `AndroidManifest.xml` |
| `MANIFEST_INVALID` | 422 | Manifest present but unreadable (bad AXML, no package, wrong root) |
| `VALIDATOR_MUST_DIFFER` | 409 | `discovered_by == validated_by` (ADR-010) |
| `MISSING_EVIDENCE` | 422 | A validation was requested with no `evidence_refs` |
| `INTENSITY_DISABLED` | 409 | Intensity above the global v1 ceiling, whatever was granted |
| `NOT_FOUND` | 404 | Unknown application, scan or evidence id |
| `APK_DUPLICATE` | 409 | Same SHA-256 exists; retry with `?force=true` |
| `SCAN_STATE_CONFLICT` | 409 | e.g. pause on a `CLOSED` scan |
| `TOOL_UNAVAILABLE` | 503 | Required binary missing on the analysis host (NFR-PORT-1) |
| `BUDGET_EXHAUSTED` | 409 | Budget already spent |
| `EVIDENCE_DANGLING` | 500 | Integrity violation; should be impossible, surfaced loudly |
| `IDEMPOTENCY_CONFLICT` | 409 | Same key, different body |
| `CODE_INDEX_FAILED` | 422 | The APK has no readable `classes.dex`, or androguard could not parse it |
| `MODEL_CONSENT_REQUIRED` | 409 | A model-backed route was called without the required per-investigation consent, gateway, or a reviewer model that differs from the producer |
| `MODEL_OUTPUT_INVALID` | 422 | Model output failed schema/integrity validation, or review input was not usable |
| `MODEL_PROVIDER_UNAVAILABLE` | 503 | Reviewer provider call failed (unreachable, timeout, or transport error); the route fails closed |

## 2a. War Room

`GET /ui` serves the War Room as one HTML document (no build step, no framework). It reads
`/api/v1` exclusively: the scan list, the selected scan, RECON's surface, findings with their gate
evidence, the event log replayed from `GET /scans/{id}/events`, and a link to the stored report.
`GET /` redirects to `/ui`. Every panel has an empty state that says the data is absent rather
than filling the space.

## 3. Endpoints

### 3.1 Applications

#### `POST /applications`
Upload an APK.

```http
POST /api/v1/applications
Content-Type: multipart/form-data

file=@diva-beta.apk
```
```json
201 Created
{
  "id": "app_01J8ZQ3K7Y",
  "sha256": "9f2c…",
  "package_name": "jakhar.aseem.diva",
  "version_name": "1.0",
  "version_code": 1,
  "min_sdk": 21,
  "target_sdk": 30,
  "file_size": 1482351,
  "created_at": "2026-11-12T09:14:02Z"
}
```

Validation: ZIP magic, presence of `AndroidManifest.xml`, size ≤ 200 MB, hash computed streaming.
The upload is **stored, never executed by the API process** (NFR-SEC-3).

#### `GET /applications` · `GET /applications/{id}` · `DELETE /applications/{id}`
`DELETE` is a soft delete that refuses while a live investigation references the application.

### 3.2 Authorisations

#### `POST /authorizations`
```json
{
  "apk_sha256": "9f2c…",
  "target_package": "jakhar.aseem.diva",
  "scope_text": "Static and controlled dynamic analysis of DIVA test build for graduation evaluation; owner is the project team.",
  "max_intensity": 2,
  "expires_at": "2026-12-31T23:59:59Z",
  "statement": "I confirm I own or am authorised to test this application."
}
```
`scope_text` min length 20 and `statement` non-empty are enforced server-side; they are not a checkbox
formality, they are the audit record.

### 3.3 Investigations ("scans")

#### `POST /scans`
```json
{
  "application_id": "app_01J8ZQ3K7Y",
  "authorization_id": "…",
  "objective": "Determine whether exported components expose privileged functionality reachable by an unprivileged third-party app.",
  "intensity": 1,
  "budget": {
    "max_steps": 60,
    "max_model_tokens": 400000,
    "max_tool_calls": 80,
    "max_wall_seconds": 1800
  },
  "llm_data_sharing": { "enabled": false }
}
```
```json
201 Created
{ "id": "scn_01J8ZR4M2P", "state": "INTAKE", "application_id": "app_01J8ZQ3K7Y", "intensity": 1 }
```
Errors: `AUTH_REQUIRED`, `INTENSITY_NOT_GRANTED`, `APK_DUPLICATE` (n/a here).

#### `GET /scans`
Investigations, newest first (`?limit=50`, max 200). Returns `{items: [...], count}` with
`id, state, objective, intensity, stop_reason, application_id, created_at`. Exists so a client can
find a scan without being told its id — a UI that hardcodes one is a demo, not a product.

#### `POST /scans/{id}/pause` · `/resume` · `/cancel`
All three are idempotent and return `{state, paused}`. `pause` sets `paused_at`/`paused_by` and leaves
`state` unchanged (ADR-017); `resume` clears them. `cancel` sets `stop_reason="cancelled"` and is the
per-scan emergency stop.

#### `POST /scans/{id}/recon`
Runs deterministic manifest analysis. Requires `state = RECON`; transitions to `SURFACE_READY`.
Emits `evidence_collected`, `surface_ready`, then `investigation_updated`. **Not idempotent** —
a second call returns `SCAN_STATE_CONFLICT`, because re-running would duplicate observations and
frontier entries.

```json
{
  "package_name": "com.example.demo", "version_name": "1.2.3", "version_code": 7,
  "min_sdk": 24, "target_sdk": 34,
  "permissions": ["android.permission.INTERNET"],
  "components": 5, "exported": 4, "unguarded_exported": 3,
  "candidates": 2, "excluded_launchers": 1, "frontier_enqueued": 2,
  "notes": ["1 exported launcher component(s) excluded as candidates: ..."],
  "evidence_id": "ev_01J8...", "state": "SURFACE_READY"
}
```

`notes` exists because the exclusions matter as much as the hits: a launcher is excluded by a
heuristic, and a component with no explicit `android:exported` has its status *inferred* from the
platform default. Both are stated rather than hidden.

#### `GET /scans/{id}/surface`
Reads back what RECON recorded: the observations (one per component, plus one for the package)
and the frontier entries it queued. Each observation carries `evidence_refs`, so every claim is
traceable to the manifest bytes.

#### `POST /scans/{id}/validate`
Evaluates a confirmation gate over supplied attributes and persists a finding plus a verdict.

```json
{ "category": "exported-component-no-permission",
  "attributes": {"exported": true, "permission": null},
  "title": "...", "description": "...", "evidence_refs": ["ev_01J8..."],
  "discovered_by": "RECON", "validated_by": "VERITAS" }
```

**Operator-asserted authority.** The attribute values here are supplied by the caller and are
not derived by the engine; a clause the caller sets to `false` rejects with the stated or mapped
reason. This endpoint is unchanged. It is an operator assertion, not engine evidence, and the
resulting finding does not show that the engine verified the attribute. Likewise the
`permission` clause only tests that a manifest permission string is present: its protection
level (`normal`, `dangerous`, `signature`) is not resolved, so a present permission is not
proof that another app cannot obtain it.

Responses are `confirmed`, `rejected` (with a `rejection_reason` from a fixed taxonomy) or
`insufficient_evidence` — the last when some clauses were not established, which is **not** the
same as "safe". With only RECON's attributes the result is always `insufficient_evidence`: RECON
cannot see whether the code behind a component reaches anything. `POST /scans/{id}/spectre` is
what supplies the missing code attributes.

#### `POST /scans/{id}/spectre`
Indexes `classes.dex`, builds the call graph, and searches from each candidate component's entry
point to a sensitive sink. Requires `state = SURFACE_READY`; runs the analysis states and emits
`code_analysis_complete`. **Deterministic: no model is called** (ADR-022), so the same APK always
produces the same result. Not idempotent in the same way as RECON — a repeat re-indexes and can
re-validate, and it will fail the state check rather than duplicate evidence.

```json
{
  "index": {"classes": 10, "methods": 34, "graph_nodes": 34,
            "internal_calls": 41, "truncated": false},
  "candidates": 1, "confirmed": 0, "rejected": 0, "manual_review": 1,
  "results": [
    { "component": "com.example.Update", "kind": "receiver",
      "reachability": "not-reached", "sink": null, "guards": [], "path_length": null,
      "verdict": "insufficient_evidence", "status": "manual_review_required",
      "rejection_reason": null,
      "explanation": "complete traversal of 6 method(s) found no catalogued sink on direct calls ...; not determined ...",
      "attributes": {"exported": true, "permission": null,
                     "sink_reachable": null, "caller_check_absent": false} }
  ]
}
```

`reachability` is `reached`, `not-reached`, `guarded`, or `unknown`. `sink_reachable` is `true`
only when a path was found. It is never `false`: a search that finds no catalogued sink (complete
or truncated) yields `null`, which becomes `insufficient_evidence` / manual review. The bounded
search fact stays on the finding as an observation (`reachability: not-reached`); it is not a
refutation, because the sink catalogue, callbacks, inter-component flows, reflection and data flow
are not modelled. A guard-like call on the path (matched by class and method name) is recorded in
`guards` but does **not** refute the "no caller check" clause: `caller_check_absent` is `null`
and the verdict is `insufficient_evidence` (manual review), never `confirmed` and never
`rejected`. Only an unguarded path gives `caller_check_absent: true`. SPECTRE no longer issues
`not-reachable` or `guarded-by-caller-check`; only independent refuting evidence could reject,
and the engine has none.

#### `POST /scans/{id}/nexus`
Drives the investigation from the frontier to `CLOSED` within a step budget. Requires
`state = SURFACE_READY` (or `CORRELATING`, where there is simply nothing left to dispatch).
Deterministic: the same APK and the same budget produce the same dispatch order and the same
verdicts, because ranking is arithmetic and no model is called (ADR-023).

This is a **dispatcher, not a planner**. It pops the best-scoring entry, hands it to the
agent that can execute it, and records what it could not do. It cannot invent a line of
enquiry that no tool queued.

```
POST /scans/{id}/nexus?max_steps=20
```

```json
{
  "state": "CLOSED",
  "stop_reason": "completed",
  "candidates": 1,
  "budget": {"max_steps": 20, "steps_used": 1, "steps_remaining": 19},
  "dispatched": 1, "dropped": 0, "remaining": 0,
  "findings": {"confirmed": 0, "rejected": 1, "manual_review": 0},
  "steps": [
    {"entry_id": "fro_...", "action": "find_api_refs", "agent": "SPECTRE",
     "disposition": "done", "reason": null}
  ],
  "notes": ["no report artefact was written: ARCHIVIST is not implemented, ..."]
}
```

When the investigation has opted in via `PUT /scans/{id}/model-consent` with `{"enabled":true,"provider":"ollama","auto_veritas":true}`, the route commits the pipeline transaction and then runs an advisory VERITAS auto-review pass over the confirmed, deterministically-produced findings, adding a `veritas_auto_review` summary block (`attempted`/`completed`/`failed`/`skipped` with fixed reason tokens; `advisory_only: true`). A pass failure is reported inside that block (`status: review-pass-error`) and never changes the scan's HTTP result. Without the flag the response is unchanged.

`stop_reason` is `completed` or `budget_exhausted`. Entries that were not run keep their state
so they can be named: `queued` when the budget stopped the loop, `dropped` when nothing could
execute them. A dropped entry always carries a `reason` — either the agent does not exist in
this build (`PHANTOM`, `VECTOR`, `ORACLE`, `ARCHIVIST`) or the current intensity forbids the
action. `max_steps` must be at least 1; a loop that may not dispatch is a no-op, so it is
rejected rather than silently doing nothing.

Once the scan is `CLOSED`, both `/spectre` and `/nexus` return `SCAN_STATE_CONFLICT`. Recovery
is a new investigation, not a retry: re-running would append a second finding for the same
component and the evidence log would claim the analysis happened twice.

#### `POST /scans/{id}/report` · `GET /scans/{id}/report`
Writes the investigation report and reads it back.

The report is **generated from stored rows**, never authored: scope and authorisation, outcome
counts, confirmed findings with their gate evidence, rejected hypotheses with their reasons, a
"Not determined" section listing findings in manual review / observations whose reachability was
never established / frontier entries that never ran, the method and its limitations, an evidence
index with SHA-256 prefixes, and an event summary. It is stored as `EvidenceKind.REPORT` and
content-addressed, so the document a reader downloads is the one the scan produced.

```
POST /scans/{id}/report   -> {"evidence_id", "sha256", "byte_size", "generated_at",
                              "markdown", "duplicate"}
GET  /scans/{id}/report   -> text/markdown; charset=utf-8
```

`404` if no report has been written. Writing a second report produces a second document: the
first write appends `report_written` (and evidence) to the investigation, so the second is built
from a state that includes the first.

NEXUS writes a report automatically during `REPORTING`, before closing the scan. If report
generation fails the scan still closes, and `report_failed` is recorded.

#### `GET /scans/{id}/stream` (SSE)
`text/event-stream`. Replays from `?after=<seq>` or the `Last-Event-ID` header, then follows.
Frames are `id: <seq>`, `event: <type>`, `data: <json>`. Once the investigation is terminal and
every event has been delivered the server emits `stream_end` and closes, so a client stops
reconnecting without guessing. Transport rationale: ADR-021.

#### `GET /scans/{id}`
```json
{
  "id": "scn_01J8ZR4M2P",
  "state": "SELECTING",
  "paused": false,
  "application_id": "app_01J8ZQ3K7Y",
  "step_count": 14,
  "budget": { "max_steps": 60, "max_model_tokens": 400000, "max_tool_calls": 80, "max_wall_seconds": 1800 },
  "used":   { "steps": 14, "model_tokens": 91234, "tool_calls": 19, "wall_seconds": 342 },
  "counts": { "observations": 37, "hypotheses": 6, "findings": { "confirmed": 1, "rejected": 2, "pending": 3 } },
  "last_event_seq": 208
}
```
`used` and `budget` are always adjacent so the UI cannot show progress without the denominator.

#### `GET /scans/{id}/agents`
```json
[
  {
    "name": "SPECTRE",
    "status": "executing_tool",
    "objective": "Inspect ExportActivity.onCreate for caller verification",
    "current_action": "decompile_method",
    "current_target": "com.example.ExportActivity#onCreate",
    "tool": "jadx",
    "last_activity_at": "2026-11-12T09:21:44Z",
    "counters": { "tool_calls": 6, "observations": 11, "errors": 0 }
  },
  { "name": "PHANTOM", "status": "unavailable", "reason": "no emulator host; intensity 1" }
]
```
`unavailable` is a first-class status. Agents do not silently vanish from the UI.

#### `GET /scans/{id}/observations?kind=&maswe=&agent=&after=`
Cursor-paginated. Returns observation objects as in `AGENT_DESIGN.md §3`.

#### `GET /scans/{id}/hypotheses?status=`
Includes `required_evidence` vs `satisfied_evidence` so the UI can show *why* something is still open —
this is the most informative view in the product.

#### `GET /scans/{id}/decisions?after=`
The audit trail of choices, including rejected alternatives and full model provenance
(provider, requested/actual model, role, prompt version, prompt/input/schema/response
SHA-256, validated output, token usage, latency, generation parameters). Deterministic
decisions record no provider/model. Pagination is keyset-based and bounded: rows are
returned in deterministic (`created_at`, `id`) order, at most `limit` per call (default
100, max 200); `after` takes a DecisionRow id from the same scan (unknown or cross-scan
cursors are 404) and returns only later rows. Follow `next_cursor` while it is non-null
for a complete, non-overlapping replay. Owner-scoped.

#### `POST /scans/{id}/findings/{finding_id}/veritas-review?producer_model_id=`
Runs the advisory VERITAS challenge (D-026) against one finding of this scan:
a different, provider-resolved model reviews the finding confined to its persisted
evidence references. Consent-gated (`PUT /scans/{id}/model-consent`), budgeted, and
persisted with DecisionRow/event provenance. Advisory only: deterministic gates remain
the sole verdict authority. If the finding has a persisted producer model decision,
`producer_model_id` must match it (conflict: `MODEL_OUTPUT_INVALID` 422) and the
response reports `producer_model_verified: true` with `independence_assured: true`;
otherwise the caller-supplied producer is unverified and the response says so
(`producer_model_verified: false`, `independence_assured: false`) - reviewer distinctness
is then checked against the claim but not proven. In the shipped version the
finding-producer action registry is EMPTY (no model-backed finding producer exists;
findings come from deterministic gates), so independence is ALWAYS unverified in
practice - the verified path is a documented future capability, exercised today only
by tests with a registered mock production action. Fails closed with
`MODEL_CONSENT_REQUIRED` when no model gateway/consent is in place, `BUDGET_EXHAUSTED`
409 when the investigation token budget is spent, `MODEL_PROVIDER_UNAVAILABLE` 503 when
the provider call fails (stable message; transport details never leave the server),
and 404 when the finding is not part of this scan.

#### `GET /scans/{id}/findings?status=&severity=`
```json
{
  "items": [
    {
      "id": "fnd_01J8ZS…",
      "title": "Exported activity exposes unvalidated intent extras to a privileged data write",
      "category": "exported-component-no-permission",
      "severity": "high",
      "severity_vector": "CVSS:4.0/AV:L/AC:L/AT:P/PR:N/UI:N/VC:H/…",
      "confidence": 0.82,
      "status": "confirmed",
      "masvs": ["MASVS-PLATFORM-3"],
      "maswe": ["MASWE-0029"],
      "source_ref": { "file": "sources/com/example/ExportActivity.java",
                      "class": "com.example.ExportActivity", "method": "onCreate", "lines": [42, 68] },
      "evidence_refs": ["ev_01J8ZS…", "ev_01J8ZT…"],
      "discovered_by": "SPECTRE",
      "validated_by": "VERITAS",
      "gate_evidence": {
        "exported": true, "no_permission": true,
        "caller_check_absent": true, "sink_reachable": true
      }
    }
  ],
  "next_after": null
}
```

#### `GET /scans/{id}/evidence/{evidence_id}`
Metadata + a short `text_preview` (≤ 8 KB) unless `?raw=true`, which streams the blob with
`Content-Disposition: attachment` and `X-Content-Type-Options: nosniff`. **Never** rendered as HTML.

#### `GET /scans/{id}/attack-graph?node_id=&depth=2&min_assertion=observed`
```json
{
  "nodes": [ { "id": "gph_1", "type": "activity", "label": "ExportActivity",
               "assertion": "observed", "evidence_refs": ["ev_…"] } ],
  "edges": [ { "id": "gph_e1", "source": "gph_1", "target": "gph_7",
               "relation": "reaches", "assertion": "confirmed",
               "rationale": "onCreate passes getStringExtra(\"path\") to FileOutputStream",
               "evidence_refs": ["ev_…"] } ],
  "truncated": false,
  "bounds": { "depth_applied": 2, "node_cap": 500 }
}
```
`depth` is clamped to 3. A `node_cap` is enforced server-side; `truncated: true` tells the UI it must
offer "expand instead of show everything" (FR-GRAPH-3).

#### `POST /scans/{id}/report`
```json
{ "format": "pdf", "include_rejected": true, "include_unknowns": true }
```
`include_unknowns` defaults to `true`, and setting it to `false` is rejected with `422` — an intentional product
decision: reports that hide what was not determined are misleading.

#### `GET /scans/{id}/report?version=1` → file stream

#### `POST /scans/{id}/ask`
Analyst asks NEXUS a question about the current investigation.
```json
{ "question": "Why did you stop investigating the provider?" }
```
```json
{
  "answer": "The provider was exported but openFile canonicalises the path with getCanonicalPath() and compares the prefix against the app's private dir before opening. That satisfies the path-traversal gate's negative condition, so the hypothesis was refuted rather than confirmed.",
  "grounded_on": ["obs_01J8…", "dec_01J8…", "hyp_01J8…"],
  "answered_by": "NEXUS",
  "model_id": "…"
}
```
**Constraint:** the answer must cite observation/decision IDs that exist in this scan. Answers without
grounding are rejected by a post-generation validator and reframed as "no evidence found in this
investigation" — this is the anti-hallucination control for the chat surface.

### 3.4 Approvals

#### `GET /approvals?state=pending` · `POST /approvals/{id}/grant` · `/reject`
```json
{
  "id": "apr_01J8…",
  "scan_id": "scn_…",
  "requested_action": "frida_instrument",
  "intensity_required": 2,
  "granted_intensity": 1,
  "justification": "Verify that ExportActivity accepts the crafted intent at runtime.",
  "risk_summary": "Writes to /sdcard/Download/test.txt in an isolated emulator. No network.",
  "expires_at": "2026-11-12T10:00:00Z"
}
```
Approvals expire. An expired approval that was never used is recorded as such — the audit trail
includes what was *avoided*.

### 3.5 System

`GET /health` → `{status, db, artifact_store, tools: {jadx: "1.5.6", apktool: "absent", …}}`
`GET /system/tools` → per-tool availability + version, which the UI shows before a scan starts so the
user knows PHANTOM will be unavailable *before* waiting 20 minutes.

## 4. WebSocket protocol

### 4.1 Connect
```
GET /ws/scans/{scan_id}?token=<jwt>&after=<last_seq>
Upgrade: websocket
```

### 4.2 Server → client frames
```json
{ "type": "event", "seq": 208, "event": { "type": "observation_created", "payload": { … }, "at": "…" } }
{ "type": "hello", "current_seq": 208, "state": "SELECTING", "replay_from": 120 }
{ "type": "gap", "from_seq": 120, "to_seq": 208 }
{ "type": "heartbeat", "at": "2026-11-12T09:30:00Z" }
{ "type": "error", "code": "SCAN_NOT_FOUND", "detail": "…" }
```

### 4.3 Client → server
```json
{ "type": "ack", "seq": 208 }
{ "type": "ping" }
```
That is the entire protocol. Deliberately minimal: **clients cannot mutate scan state over the
WebSocket.** All mutations go through REST where they are authorised, validated and audited. Mixing
command and event channels on one socket is a common source of untraceable actions.

### 4.4 Ordering, gaps and reconnect (FR-WAR-1/2)

- `seq` is monotonic per scan and gapless (asserted in `tests/integrity/`).
- On reconnect with `after=N`, the server replays events `N+1 … current_seq` from the table, then
  switches to live. If the requested range exceeds the in-memory buffer, replay comes from Postgres —
  correctness does not depend on the buffer.
- If the client detects `seq > last+1`, it must render an explicit "history gap" marker rather than
  silently jumping. Hiding gaps would make the feed untrustworthy.

### 4.5 Backpressure
Per-connection bounded queue (default 1000). On overflow the server sends `gap` and closes; the client
reconnects with `after=last_seq`. This is the correct failure: dropping events silently would
compromise the audit view.

## 5. Request/response schemas — Pydantic source

All models live in `mobius/schemas/` (Layer 1, no I/O). Example:

```python
class ScanCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")     # reject unknown fields
    application_id: Annotated[str, Field(pattern=r"^app_[0-9A-HJKMNP-TV-Z]{26}$")]
    authorization_id: str
    objective: Annotated[str, Field(min_length=10, max_length=2000)]
    intensity: Annotated[int, Field(ge=0, le=3)] = 0
    budget: ScanBudget = ScanBudget()
    llm_data_sharing: LLMSharing = LLMSharing(enabled=False)
```

`extra="forbid"` everywhere: silently ignoring a misspelled field (`intesity`) is a security bug in a
tool whose configuration controls sandbox policy.

## 6. Versioning & deprecation

Additive within v1. A field removal requires v2 and a 3-month overlap. Response models never remove
fields; they may add optional ones. Clients must ignore unknown fields (stated, and tested with a
contract test).

## 7. Open questions

| # | Question |
|---|---|
| Q1 | Multi-user: is a shared scan visible to all `analyst` roles, or owner-only with explicit sharing? |
| Q2 | Should `POST /scans` accept a *saved objective template* (MASVS category subset) to make the product usable by non-experts? |
| Q3 | Export formats: PDF generation adds a dependency (WeasyPrint/ReportLab) — is Markdown + print-to-PDF sufficient for submission? |


## Attack graph API and UI (D-033)

- `POST /api/v1/scans/{scan_id}/graph/rebuild` runs the D-030 projection, D-031 direct correlation, and D-032 candidate-path builder. It appends an `attack_graph_rebuilt` event.
- `GET /api/v1/scans/{scan_id}/graph` returns React Flow-compatible nodes and edges with assertion levels, rationale, evidence references, and candidate-path prerequisites/missing proof.
- Both routes enforce investigation ownership. Graph presentation never changes findings or verdicts.
- The React Flow client is served at `/ui/graph`; build with `npm install && npm run build` in `frontend/`.
