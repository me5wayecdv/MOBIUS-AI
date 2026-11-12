# DATABASE SCHEMA

**Status:** Proposed
**Target:** PostgreSQL 16
**Portability:** avoids Postgres-only constructs except `JSONB`, `LISTEN/NOTIFY`, and `FOR UPDATE SKIP LOCKED` — see §7 for the SQLite dev fallback.

---

## 1. Design principles

1. **Append-only where audit matters.** Events, evidence and decisions are insert-only. No `UPDATE` on
   an event. Corrections are new events referencing the old one.
2. **Immutable identity.** An `Application` is identified by its SHA-256. Re-uploading the same bytes
   is not a new application.
3. **Separation of fact and belief.** `observations` (seen) vs `hypotheses` (believed) vs `findings`
   (asserted, validated) are three tables, not one polymorphic "result" table.
4. **Evidence is content-addressed.** `evidence.sha256` is unique per scan; identical blobs dedupe.
5. **Nothing important is stored only in memory.** The frontier, FSM state and budgets are all rows
   (FR-NEXUS-7).
6. **No soft-delete on findings.** `REJECTED` is a status, not a deletion (FR-VER-5).

## 2. Entity map

```mermaid
erDiagram
    USER ||--o{ AUTHORIZATION : grants
    AUTHORIZATION ||--o{ INVESTIGATION : permits
    APPLICATION ||--o{ INVESTIGATION : target_of
    APPLICATION ||--o{ EVIDENCE : has
    INVESTIGATION ||--o{ EVENT : emits
    INVESTIGATION ||--o{ OBSERVATION : produces
    INVESTIGATION ||--o{ HYPOTHESIS : holds
    INVESTIGATION ||--o{ DECISION : records
    INVESTIGATION ||--o{ FRONTIER_ENTRY : queues
    INVESTIGATION ||--o{ FINDING : asserts
    INVESTIGATION ||--o{ TOOL_EXECUTION : runs
    INVESTIGATION o|--o| REPORT : summarised_by
    OBSERVATION }o--o{ EVIDENCE : references
    HYPOTHESIS }o--o{ OBSERVATION : derived_from
    FINDING }o--o{ EVIDENCE : supported_by
    FINDING ||--o{ VERDICT : validated_by
    INVESTIGATION ||--o{ GRAPH_NODE : contains
    GRAPH_NODE ||--o{ GRAPH_EDGE : source
```

## 3. Tables

### 3.1 Identity & authorisation

```sql
CREATE TABLE users (
    id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    email         citext UNIQUE NOT NULL,
    display_name  text NOT NULL,
    role          text NOT NULL CHECK (role IN ('analyst','reviewer','admin')),
    password_hash text NOT NULL,           -- argon2id
    created_at    timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE authorizations (
    id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    granted_by     uuid NOT NULL REFERENCES users(id),
    target_package text NOT NULL,
    apk_sha256     char(64) NOT NULL,      -- pinned; FR-AUTH-3
    scope_text     text NOT NULL CHECK (length(scope_text) >= 20),
    max_intensity  smallint NOT NULL CHECK (max_intensity BETWEEN 0 AND 3),
    statement      text NOT NULL,          -- signed assertion of ownership/permission
    expires_at     timestamptz NOT NULL,
    revoked_at     timestamptz,
    created_at     timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT authorization_expiry_sane CHECK (expires_at > created_at)
);
CREATE INDEX ON authorizations (apk_sha256) WHERE revoked_at IS NULL;
```

### 3.2 Applications & investigations

```sql
CREATE TABLE applications (
    id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    sha256         char(64) UNIQUE NOT NULL,
    package_name   text,
    version_name   text,
    version_code   bigint,
    min_sdk        smallint,
    target_sdk     smallint,
    file_size      bigint NOT NULL,
    artifact_key   text NOT NULL,          -- object-store key; NEVER a repo path
    uploaded_by    uuid REFERENCES users(id),
    created_at     timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE investigations (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    application_id  uuid NOT NULL REFERENCES applications(id),
    authorization_id uuid REFERENCES authorizations(id),
    created_by      uuid NOT NULL REFERENCES users(id),
    objective       text NOT NULL,
    intensity       smallint NOT NULL DEFAULT 0 CHECK (intensity BETWEEN 0 AND 3),
    state           text NOT NULL,          -- FSM state, see ARCHITECTURE.md §4
    budget_json     jsonb NOT NULL,         -- steps, tokens, wall clock, tool calls
    used_json       jsonb NOT NULL DEFAULT '{}'::jsonb,
    llm_data_sharing jsonb NOT NULL DEFAULT '{"enabled": false}'::jsonb,
    started_at      timestamptz,
    finished_at     timestamptz,
    stop_reason     text,                   -- completed | budget_exhausted | cancelled | error
    created_at      timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT state_known CHECK (state IN (
        'INTAKE','SCOPE_BLOCKED','RECON','SURFACE_READY','SELECTING','DISPATCHING',
        'OBSERVING','VALIDATING','AWAITING_APPROVAL','CORRELATING','REPORTING',
        'CLOSED','BUDGET_EXHAUSTED','CANCELLED','FAILED')),
    CONSTRAINT intensity_within_authorization CHECK (intensity BETWEEN 0 AND 3)
);
CREATE INDEX ON investigations (state) WHERE finished_at IS NULL;
CREATE INDEX ON investigations (application_id, created_at DESC);
```

**Partial index rationale:** the worker's hot query is "which investigations are live". A partial index
on `finished_at IS NULL` keeps that O(live) rather than O(all).

### 3.3 Event store (append-only)

```sql
CREATE TABLE events (
    id              bigserial PRIMARY KEY,
    investigation_id uuid NOT NULL REFERENCES investigations(id),
    seq             bigint NOT NULL,          -- monotonic per investigation; FR-WAR-1
    type            text NOT NULL,
    payload         jsonb NOT NULL,
    actor           text,                     -- 'NEXUS' | 'RECON' | 'system'
    created_at      timestamptz NOT NULL DEFAULT now(),
    UNIQUE (investigation_id, seq)
);
CREATE INDEX ON events (investigation_id, seq);
CREATE INDEX ON events (investigation_id, type, created_at DESC);
```

`seq` is allocated inside the same transaction as the state change, via
`SELECT coalesce(max(seq),0)+1 FROM events WHERE investigation_id=$1 FOR UPDATE` on the investigation
row — or a dedicated `investigation_seq` counter column. **Simpler and preferred:** keep
`investigations.event_seq bigint NOT NULL DEFAULT 0` and `UPDATE ... RETURNING event_seq` — one row
lock, no aggregate scan. The `UNIQUE(investigation_id, seq)` constraint is the real guarantee.

### 3.4 Observation / hypothesis / decision

```sql
CREATE TABLE evidence (
    id              uuid PRIMARY KEY,
    investigation_id uuid NOT NULL REFERENCES investigations(id),
    kind            text NOT NULL,           -- manifest|source|smali|dex-string|tool-output|http|logcat|config|certificate|screenshot
    sha256          char(64) NOT NULL,
    object_key      text NOT NULL,
    byte_size       bigint NOT NULL,
    truncated       boolean NOT NULL DEFAULT false,
    redacted        boolean NOT NULL DEFAULT false,
    summary         text NOT NULL,           -- survives blob pruning
    produced_by     text NOT NULL,
    created_at      timestamptz NOT NULL DEFAULT now(),
    UNIQUE (investigation_id, sha256)        -- dedupe identical blobs
);

CREATE TABLE observations (
    id              uuid PRIMARY KEY,
    investigation_id uuid NOT NULL REFERENCES investigations(id),
    agent           text NOT NULL,
    kind            text NOT NULL CHECK (kind IN ('fact','inference','anomaly')),
    fidelity        text NOT NULL CHECK (fidelity IN ('binary-xml','decompiled','smali',
                                                     'decompiler-failed','runtime','config')),
    subject_type    text,
    subject_ref     text,
    statement       text NOT NULL,
    attributes      jsonb NOT NULL DEFAULT '{}'::jsonb,
    maswe           text[] NOT NULL DEFAULT '{}',
    confidence      numeric(3,2) NOT NULL CHECK (confidence BETWEEN 0 AND 1),
    evidence_refs   uuid[] NOT NULL,
    created_at      timestamptz NOT NULL DEFAULT now(),
    -- AC-FR-RECON-7: a fact without evidence is a bug, enforced by the database
    CONSTRAINT facts_have_evidence
        CHECK (kind <> 'fact' OR cardinality(evidence_refs) > 0),
    CONSTRAINT facts_are_certain
        CHECK (kind <> 'fact' OR confidence = 1.00)
);
CREATE INDEX ON observations (investigation_id, subject_ref);
CREATE INDEX ON observations USING gin (maswe);

CREATE TABLE hypotheses (
    id              uuid PRIMARY KEY,
    investigation_id uuid NOT NULL REFERENCES investigations(id),
    claim           text NOT NULL,
    maswe           text[] NOT NULL DEFAULT '{}',
    derived_from    uuid[] NOT NULL,
    required_evidence text[] NOT NULL,       -- declared BEFORE testing
    satisfied_evidence text[] NOT NULL DEFAULT '{}',
    status          text NOT NULL DEFAULT 'open'
                    CHECK (status IN ('open','testing','supported','refuted','abandoned','parked')),
    priority        numeric(4,3) NOT NULL DEFAULT 0.5,
    depth           smallint NOT NULL DEFAULT 0,
    parent_id       uuid REFERENCES hypotheses(id),
    created_at      timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE decisions (
    id              uuid PRIMARY KEY,
    investigation_id uuid NOT NULL REFERENCES investigations(id),
    agent           text NOT NULL,
    action          text NOT NULL,
    action_args     jsonb NOT NULL,
    considered_evidence uuid[] NOT NULL,
    alternatives    jsonb NOT NULL DEFAULT '[]'::jsonb,
    expected_outcome text NOT NULL,
    uncertainty     text,
    prompt_version  text,                    -- traceability of the prompt that produced it
    model_id        text,
    created_at      timestamptz NOT NULL DEFAULT now()
);
```

Note `facts_are_certain`: this encodes a methodological rule in the schema — an observation typed as a
*fact* must have confidence exactly 1.0. Anything less is an `inference`. The database will not let the
code blur that line, which is exactly the failure mode that turns an investigator into a scanner.

### 3.5 Frontier (persisted planning state)

```sql
CREATE TABLE frontier_entries (
    id              uuid PRIMARY KEY,
    investigation_id uuid NOT NULL REFERENCES investigations(id),
    action          text NOT NULL,
    action_args     jsonb NOT NULL,
    required_agent  text NOT NULL,
    relates_to_maswe text[] NOT NULL DEFAULT '{}',
    score           numeric(6,5) NOT NULL,
    depth           smallint NOT NULL DEFAULT 0,
    state           text NOT NULL DEFAULT 'queued'
                    CHECK (state IN ('queued','leased','done','dropped','failed')),
    lease_owner     text,
    lease_expires_at timestamptz,
    attempts        smallint NOT NULL DEFAULT 0,
    inserted_at     timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX frontier_pick ON frontier_entries (investigation_id, state, score DESC);

-- Worker claims one entry atomically; no broker required.  (ADR-007)
-- SELECT * FROM frontier_entries
--  WHERE investigation_id = $1 AND state = 'queued'
--  ORDER BY score DESC
--  FOR UPDATE SKIP LOCKED LIMIT 1;
```

### 3.6 Tool execution

```sql
CREATE TABLE tool_executions (
    id              uuid PRIMARY KEY,
    investigation_id uuid NOT NULL REFERENCES investigations(id),
    tool            text NOT NULL,
    tool_version    text NOT NULL,           -- reproducibility; AGENT_DESIGN.md §7.1
    argv            jsonb NOT NULL,          -- the exact argv list, for audit
    status          text NOT NULL CHECK (status IN ('ok','error','timeout','unavailable','killed')),
    exit_code       integer,
    duration_ms     integer NOT NULL,
    peak_rss_kb     integer,
    stdout_evidence uuid REFERENCES evidence(id),
    stderr_tail     text,
    requested_by    uuid REFERENCES decisions(id),
    created_at      timestamptz NOT NULL DEFAULT now()
);
```

### 3.7 Findings & verdicts

```sql
CREATE TABLE findings (
    id              uuid PRIMARY KEY,
    investigation_id uuid NOT NULL REFERENCES investigations(id),
    title           text NOT NULL,
    category        text NOT NULL,           -- maps to a gate in AGENT_DESIGN.md §6
    description     text NOT NULL,
    component_ref   text,
    source_ref      jsonb,                   -- {file, class, method, lines:[a,b]}
    evidence_refs   uuid[] NOT NULL,
    masvs           text[] NOT NULL DEFAULT '{}',
    maswe           text[] NOT NULL DEFAULT '{}',
    mastg           text[] NOT NULL DEFAULT '{}',
    -- independence, per master prompt §8  (never averaged into one score)
    severity        text NOT NULL CHECK (severity IN ('info','low','medium','high','critical')),
    severity_vector text,                    -- CVSS 4.0 vector string where applicable
    confidence      numeric(3,2) NOT NULL CHECK (confidence BETWEEN 0 AND 1),
    status          text NOT NULL CHECK (status IN (
        'discovered','under_investigation','potential','awaiting_validation',
        'confirmed','rejected','manual_review_required')),
    discovered_by   text NOT NULL,
    validated_by    text,
    gate_evidence   jsonb NOT NULL DEFAULT '{}'::jsonb,  -- which gate clauses passed
    remediation     text,
    reproduction    jsonb,
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT confirmed_requires_validator
        CHECK (status <> 'confirmed' OR validated_by IS NOT NULL),
    CONSTRAINT confirmed_needs_evidence
        CHECK (status <> 'confirmed' OR cardinality(evidence_refs) > 0)
);

CREATE TABLE verdicts (
    id              uuid PRIMARY KEY,
    finding_id      uuid NOT NULL REFERENCES findings(id),
    verdict         text NOT NULL CHECK (verdict IN
                     ('confirmed','rejected','needs_manual_review','insufficient_evidence')),
    rejection_reason text CHECK (
        verdict <> 'rejected' OR rejection_reason IS NOT NULL),   -- FR-VER-4
    rationale       text NOT NULL,
    gate_passed     boolean NOT NULL,
    gate_detail     jsonb NOT NULL,
    validated_by    text NOT NULL,
    model_id        text,
    created_at      timestamptz NOT NULL DEFAULT now()
);
```

### 3.8 Attack graph

```sql
CREATE TABLE graph_nodes (
    id              uuid PRIMARY KEY,
    investigation_id uuid NOT NULL REFERENCES investigations(id),
    node_type       text NOT NULL,   -- activity|service|receiver|provider|class|method|
                                     -- endpoint|secret|control|hypothesis|finding
    label           text NOT NULL,
    ref             text,            -- component name / class#method / URL
    assertion       text NOT NULL CHECK (assertion IN
                     ('observed','hypothesis','confirmed','rejected')),
    attributes      jsonb NOT NULL DEFAULT '{}'::jsonb,
    evidence_refs   uuid[] NOT NULL DEFAULT '{}',
    created_at      timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX ON graph_nodes (investigation_id, node_type);

CREATE TABLE graph_edges (
    id              uuid PRIMARY KEY,
    investigation_id uuid NOT NULL REFERENCES investigations(id),
    source_id       uuid NOT NULL REFERENCES graph_nodes(id),
    target_id       uuid NOT NULL REFERENCES graph_nodes(id),
    relation        text NOT NULL,   -- calls|invokes|exposes|reads|writes|sends_to|
                                     -- receives_from|reaches|validates|bypasses
    assertion       text NOT NULL CHECK (assertion IN
                     ('observed','hypothesis','confirmed','rejected')),
    rationale       text,
    evidence_refs   uuid[] NOT NULL DEFAULT '{}',
    UNIQUE (investigation_id, source_id, target_id, relation),
    -- AC-FR-GRAPH-2: a hypothesised edge must say why
    CONSTRAINT hypothesis_states_why
        CHECK (assertion <> 'hypothesis' OR (rationale IS NOT NULL AND length(rationale) > 0))
);
CREATE INDEX ON graph_edges (investigation_id, source_id);
CREATE INDEX ON graph_edges (investigation_id, target_id);
```

### 3.9 Reports & audit

```sql
CREATE TABLE reports (
    id              uuid PRIMARY KEY,
    investigation_id uuid NOT NULL REFERENCES investigations(id),
    version         integer NOT NULL,
    format          text NOT NULL CHECK (format IN ('markdown','pdf','json')),
    object_key      text NOT NULL,
    content_sha256  char(64) NOT NULL,
    coverage        jsonb NOT NULL,   -- {actions_done, frontier_abandoned, phases_skipped}
    created_at      timestamptz NOT NULL DEFAULT now(),
    UNIQUE (investigation_id, version)
);

CREATE TABLE audit_log (
    id          bigserial PRIMARY KEY,
    actor       text NOT NULL,
    action      text NOT NULL,
    target      text,
    detail      jsonb,
    ip          inet,
    created_at  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX ON audit_log (created_at DESC);
```

## 4. Why PostgreSQL alone is sufficient (and no graph DB)

| Need | Postgres answer |
|---|---|
| Durable ordered event stream | `events` table + `LISTEN/NOTIFY` |
| Job queue | `FOR UPDATE SKIP LOCKED` |
| Semi-structured observations | `JSONB` + GIN when needed |
| Attack graph traversal | Adjacency tables + recursive CTE (§5) |
| Full-text search over findings | `tsvector` |
| Vector similarity | **Not needed.** No embedding-based retrieval is in scope; adding `pgvector` would imply a feature that does not exist. |

Scale estimate: a heavy scan produces ~10³ observations, ~5×10² nodes, ~2×10³ events. Postgres handles
this trivially. Neo4j would add a service, a second query language, and a consistency problem between
the relational record and the graph — for zero benefit at this scale (ADR-006).

## 5. Graph queries that must be fast

```sql
-- Bounded neighbourhood expansion (FR-GRAPH-3), depth capped by the API at 3
WITH RECURSIVE walk(id, depth) AS (
    SELECT $1::uuid, 0
  UNION
    SELECT e.target_id, w.depth + 1
    FROM walk w
    JOIN graph_edges e ON e.source_id = w.id
    WHERE w.depth < $2 AND e.assertion <> 'rejected'
)
SELECT DISTINCT n.* FROM walk JOIN graph_nodes n ON n.id = walk.id;
```

```sql
-- Path from entry point to a finding, only over edges at or above an assertion level
-- (FR-GRAPH-4). Assertion levels are compared via a small lookup, not string ordering.
SELECT * FROM pgr_path(...);  -- implemented in app code with a bidirectional BFS for clarity
```

Recursive CTEs with a depth bound are the right tool: they are readable by a student, testable, and
avoid a second database. Use `CYCLE` detection (Postgres 14+) to prevent infinite loops on cyclic
graphs, which real call graphs always are.

## 6. Retention

| Data | Retention | Mechanism |
|---|---|---|
| APK artefacts | 30 d after investigation close | object-store lifecycle rule |
| Decompiled cache | until APK artefact pruned | keyed by APK hash |
| Tool stdout blobs > 1 MB | gzip; prune payload after 30 d, keep `summary` + hash | maintenance job |
| Evidence rows | retained (small) | — |
| Events, decisions, verdicts, reports | retained permanently | these *are* the audit trail |
| `audit_log` | 1 y | partition by month if it grows |

## 7. SQLite fallback (dev only)

`JSONB` → `JSON`, `uuid` → `TEXT`, `LISTEN/NOTIFY` → in-process asyncio, `SKIP LOCKED` → single-worker
only, `citext` → `TEXT COLLATE NOCASE`, arrays → JSON. This is a **demo fallback**, not a deployment
target, and CI must run the real Postgres. Declaring it keeps the schema honest about which Postgres
features are load-bearing.

## 8. Migration & integrity tests

- Alembic migrations; every migration tested forward **and** backward on a seeded DB.
- `tests/integrity/` runs after each E2E scan:
  1. no dangling `evidence_refs` in observations/findings/graph (FR-EV-3),
  2. every `confirmed` finding has ≥ 1 `verdict` with `gate_passed = true`,
  3. every investigation in a terminal state has a report or a `stop_reason`,
  4. `events` seq is gapless per investigation.
- These four assertions are the machine-checkable version of the project's honesty claims. They should
  run in CI and fail the build.
