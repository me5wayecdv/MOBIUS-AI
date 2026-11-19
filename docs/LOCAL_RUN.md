# Local self-host run

Two ways to run the full War Room stack on one machine:

- **Option B (no Docker)** is the verified path: run end to end on
  2026-11-19 on Python 3.12 / PostgreSQL 16 (real pinned APK, upload to
  report; see "Verification status" at the bottom).
- **Option A (Docker Compose)** is a candidate, not yet validated: the
  definition follows the same verified steps, but no Docker host was
  available where this was prepared. Run `docker compose up --build` once
  locally before relying on it; treat it as unverified until then.

What you get: APK upload, RECON manifest/surface analysis, inline multi-DEX
indexing, SPECTRE reachability, NEXUS investigation, attack graph, PoC lab
(local harnesses only), Markdown report, War Room UI.

## Option A: Docker Compose (candidate - unverified)

Prerequisites: Docker with the Compose plugin (`docker compose version`).

```sh
docker compose up --build --detach
scripts/healthcheck.sh          # waits for http://127.0.0.1:8000/api/v1/health
```

Open http://127.0.0.1:8000/ for the War Room. Data persists in the
`mobius-pgdata` and `mobius-artifacts` volumes; `docker compose down -v`
deletes everything.

The stack binds 127.0.0.1 only. The API's analyst identity is a development
stub (`analyst-1`, see docs/INVESTIGATION_OWNERSHIP.md): this delivery is
single-user local use, not multi-user hosting.

## Option B: no Docker (Python + PostgreSQL + Node) - verified

Verified on Python 3.12, PostgreSQL 16, Node 22. The database role/database
steps need a PostgreSQL account with CREATEDB/CREATEROLE authority (usually
the `postgres` superuser, e.g. via `sudo -u postgres ...`); everything after
that runs as the `mobius` role.

```sh
# 1. Database (as a PostgreSQL account with CREATEDB/CREATEROLE):
createuser mobius --pwprompt        # set password: mobius_local_only
createdb -O mobius mobius

# 2. Application (as your normal user):
python -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]" && pip install "psycopg[binary]>=3.1"
export MOBIUS_DB_URL="postgresql+psycopg://mobius:mobius_local_only@localhost:5432/mobius"
export MOBIUS_ARTIFACT_ROOT="$PWD/data/artifacts"
alembic upgrade head
cd frontend && npm install --no-audit --no-fund && npm run build && cd ..

# 3. Start the server in the background (foreground blocks this terminal):
python -m uvicorn mobius.api.app:create_app --factory --host 127.0.0.1 --port 8000 &
scripts/healthcheck.sh            # waits, then prints /api/v1/health
```

Run the server in the background as shown, or open a second terminal for
`scripts/healthcheck.sh`.

## Optional: local model integration (Ollama)

Model use is off by default, consent-gated per investigation, and budgeted.
The model environment variables are read when the server starts, so set them
BEFORE starting uvicorn (exporting them afterwards has no effect):

```sh
ollama pull qwen2.5:1.5b            # any local tag; small models have limits, see below
export MOBIUS_MODEL_PROVIDER=ollama
export MOBIUS_MODEL_BASE_URL=http://127.0.0.1:11434
export MOBIUS_MODEL_NAME=qwen2.5:1.5b
# (re)start uvicorn AFTER these exports
```

Then grant consent per scan and request hypotheses:

```sh
SCAN_ID=<your scan id>
curl -fsS -X PUT -H 'Content-Type: application/json' \
  "http://127.0.0.1:8000/api/v1/scans/$SCAN_ID/model-consent" \
  -d '{"enabled": true, "provider": "ollama"}'
curl -fsS -X POST "http://127.0.0.1:8000/api/v1/scans/$SCAN_ID/nexus/hypotheses"
```

Budget: every scan carries a default budget of 400,000 model tokens
(`budget.max_model_tokens` on `POST /scans`), so no extra budget field is
needed for a first run; lower it there if you want a tighter cap. Without
consent the pipeline uses the explicitly labelled deterministic fallback.

Measured on a 1-CPU/2 GB sandbox (2026-11-19): `qwen2.5:0.5b`,
`qwen2.5:1.5b` and `qwen2.5-coder:1.5b` load and produce schema-valid JSON,
but every output was rejected by MOBIUS's integrity guards (fabricated or
wrong-kind evidence citations) and the deterministic fallback took over.
Whether a larger or different local model passes those guards is unknown -
it has not been tried. The deterministic fallback is the honest default
until a model is measured to pass.

## Optional: constrained workers and JADX source

The API enqueues DEX/RECON/JADX jobs only when immutable image digests are
configured (docs/OCI_WORKER_BACKEND.md). This is a separate deployment: the
Compose stack above does NOT wire workers, and the API container has no
access to the host's Docker socket. Running workers means running the worker
process on a host with a container runtime (outside the Compose app
container), with the cache directory shared between that host and wherever
the API reads it (`MOBIUS_JADX_CACHE_ROOT`; see
docs/ISOLATED_JADX_WORKER.md).

The only reference form the validator accepts is a real registry digest
(`<repo>@sha256:<64 hex>`): build the image, push it to a registry you
control, and pin its RepoDigest. Obtaining and resolving that reference is
part of the separate validated host setup above - there is no verified
local-image shortcut, and none is documented here. GHCR publication of the
JADX image remains a manual, owner-gated workflow and is not part of local
delivery; the JADX image stays unpublished.

## Verification status (2026-11-19)

- Option B verified end to end on clean `main` (commit c6f0b82): PostgreSQL
  16 over TCP with the exact `mobius` role/password above, `alembic upgrade
  head`, background uvicorn, `scripts/healthcheck.sh`, upload of the pinned
  Allsafe APK, scan, investigation, report. Earlier adapter-level runs:
  92,817-method multi-DEX index, JADX adapter decompilation of 2 target
  classes with jadx 1.5.6.
- Option A (Compose) and the Docker `Dockerfile`: reviewed only, never
  executed. No Docker host was available; validate before demo.
- CI smoke workflow: `scripts/local-delivery-smoke.yml` is a minimal
  startup smoke (intake + persistence + UI shell), not a pipeline run.
  Moving it into `.github/workflows/` requires the `workflow` scope, which
  the automation token used here lacks; activation is pending via the
  authorized account route.

## Known limits (unchanged by this delivery)

- Recall on the pinned 7-sample public corpus is 1/4 (CI 4.6-69.9%); no false
  positives. See `docs/BENCHMARK_RESULTS.md` and `corpus/corpus.json`.
- The PoC adapters are local simulations; runtime reproduction needs an
  emulator/device host (D-003/D-060).
- Static analysis only: no reflection, dynamic dispatch, or native code;
  every report carries its coverage manifest.
