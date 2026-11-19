# Local self-host run

Two supported ways to run the full War Room stack on one machine. The
no-Docker path below was verified end to end on 2026-11-19 (real pinned APK,
upload to report). The Compose stack is new: its definition follows the same
verified steps, but run `docker compose up --build` once locally to validate
it before demo day. A ready CI smoke workflow is included at
`scripts/local-delivery-smoke.yml`; moving it into `.github/workflows/` makes
the stack CI-verified (the current automation token has no `workflow` scope,
so that move is a one-time owner step).

What you get: APK upload, RECON manifest/surface analysis, inline multi-DEX
indexing, SPECTRE reachability, NEXUS investigation, attack graph, PoC lab
(local harnesses only), Markdown report, War Room UI.

## Option A: Docker Compose (recommended)

Prerequisites: Docker with the Compose plugin (`docker compose version`).
Status: definition reviewed, not yet executed end to end (no Docker host was
available where this was prepared). Validate once before the demo.

```sh
docker compose up --build
scripts/healthcheck.sh          # waits for http://127.0.0.1:8000/api/v1/health
```

Open http://127.0.0.1:8000/ for the War Room. Data persists in the
`mobius-pgdata` and `mobius-artifacts` volumes; `docker compose down -v`
deletes everything.

The stack binds 127.0.0.1 only. The API's analyst identity is a development
stub (`analyst-1`, see docs/INVESTIGATION_OWNERSHIP.md): this delivery is
single-user local use, not multi-user hosting.

## Option B: no Docker (Python + PostgreSQL + Node)

Verified on Python 3.12, PostgreSQL 16, Node 22:

```sh
python -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]" && pip install "psycopg[binary]>=3.1"
createdb mobius                       # or any empty PostgreSQL 14+ database
export MOBIUS_DB_URL="postgresql+psycopg://mobius:mobius_local_only@localhost:5432/mobius"
export MOBIUS_ARTIFACT_ROOT="$PWD/data/artifacts"
alembic upgrade head
cd frontend && npm install --no-audit --no-fund && npm run build && cd ..
python -m uvicorn mobius.api.app:create_app --factory --host 127.0.0.1 --port 8000
scripts/healthcheck.sh
```

## Optional: local model integration (Ollama)

Model use is off by default, consent-gated per investigation, and budgeted.
With Ollama running on the same machine:

```sh
ollama pull qwen2.5:1.5b            # any local tag; small models have limits, see below
export MOBIUS_MODEL_PROVIDER=ollama
export MOBIUS_MODEL_BASE_URL=http://127.0.0.1:11434
export MOBIUS_MODEL_NAME=qwen2.5:1.5b
```

Then grant consent per scan (`PUT /api/v1/scans/{id}/model-consent` with
`{"enabled": true, "provider": "ollama"}`) and call
`POST /api/v1/scans/{id}/nexus/hypotheses`. Without consent the pipeline uses
the explicitly labelled deterministic fallback.

Measured on a 1-CPU/2 GB sandbox (2026-11-19): models up to ~1.5B parameters
load and answer, but their output was rejected by MOBIUS's integrity guards
(fabricated or wrong-kind evidence citations). Expect to need a larger local
model and more RAM/CPU than that sandbox had before model output passes the
citation and evidence-type contracts; the deterministic fallback is the
honest default until then.

## Optional: constrained workers and JADX source

The API enqueues DEX/RECON/JADX jobs only when immutable image digests are
configured (docs/OCI_WORKER_BACKEND.md). Build the worker images locally -
no registry publication is needed:

```sh
docker build -f workers/jadx-image/Dockerfile -t mobius-jadx:local workers/jadx-image
docker inspect --format='mobius-jadx@{{index .RepoDigests 0}}' mobius-jadx:local  # or pin by image ID
export MOBIUS_JADX_IMAGE=<immutable reference>
```

The JADX worker additionally needs a shared writable cache volume
(`MOBIUS_JADX_CACHE_ROOT`) between worker and API; see
docs/ISOLATED_JADX_WORKER.md. GHCR publication of the JADX image remains a
manual, owner-gated workflow and is not part of local delivery.

## Known limits (unchanged by this delivery)

- Recall on the pinned 7-sample public corpus is 1/4 (CI 4.6-69.9%); no false
  positives. See `docs/BENCHMARK_RESULTS.md` and `corpus/corpus.json`.
- The PoC adapters are local simulations; runtime reproduction needs an
  emulator/device host (D-003/D-060).
- Static analysis only: no reflection, dynamic dispatch, or native code;
  every report carries its coverage manifest.
