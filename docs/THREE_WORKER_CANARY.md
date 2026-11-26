# Model-free three-worker API canary, preparation only

This is a recipe for a separately authorized ephemeral local test host, not an
enabled service, workflow or permission to execute. Nothing starts on checkout,
API startup, CI or import. No new images are published. No model/device is used.

## What already exists

- `.github/workflows/worker-pipeline-smoke.yml` runs the real queue consumer,
  RECON/DEX digest-pinned images and API apply routes on PostgreSQL.
- `.github/workflows/validate-provider-worker-runtime.yml` builds the provider
  image locally, resolves it through a loopback-only registry and runs the actual
  queue/OCI path. It does not publish to an external registry.
- `scripts/oci_contract_probe.py` separately tests the RECON image's mount
  contract. It is not proof of all kernel resource/network enforcement.
- `scripts/connected_journey_smoke.sh` has no configured worker consumer/images.
  It is not fixed by this recipe. Do not dispatch it as if it were ready.

## Host/deployment contract

Use a disposable host: Docker access for the host consumer is root-equivalent.
Use an empty dedicated PostgreSQL database, fresh artifact/workspace directories
and one host queue consumer for this bounded canary. The current development
analyst identity is a stub, so expose the API only on `127.0.0.1`. Do not expose
the Docker socket to the API or any parser container. The trusted host consumer
uses the runtime; parser containers receive only their bounded input mount.

Install the project with its worker extra on the host. Make PostgreSQL available
on loopback with an ephemeral test-only account, migrate with `alembic upgrade
head`, and configure the API and consumer with the SAME database and absolute
artifact root. Keep real connection strings out of shared logs/reports.

Required configuration, values independently checked on the chosen host:

| Setting | API | Host consumer |
| --- | --- | --- |
| `MOBIUS_ENV=test` | yes | yes |
| `MOBIUS_DB_URL` | dedicated migrated DB | optional |
| `MOBIUS_WORKER_DB_URL` | no | same dedicated DB |
| `MOBIUS_ARTIFACT_ROOT` | fresh absolute directory | same directory |
| `MOBIUS_WORKSPACE_ROOT` | no | fresh absolute directory |
| `MOBIUS_OCI_RUNTIME` | no | absolute Docker executable path |
| `MOBIUS_RECON_IMAGE` | actual immutable reference | identical reference |
| `MOBIUS_PROVIDER_IMAGE` | actual immutable reference | identical reference |
| `MOBIUS_DEX_IMAGE` | actual immutable reference | identical reference |
| `MOBIUS_RECON_INLINE` | unset | unset |
| model/PHANTOM settings | unset | unset |

Reuse the already-reviewed pinned RECON/DEX references from the existing worker
pipeline workflow, verifying their availability at execution. For provider,
follow the existing provider validation workflow's local build and loopback-only
registry procedure. Obtain the real resolved RepoDigest, never invent one or use
a mutable tag as a digest. No GHCR login/publication is needed. Do not run any
publication workflow. A local image build/download is still runtime work and
requires the separate go-ahead.

Start API with `python -m uvicorn mobius.api.canary_app:create_canary_app --factory --host
127.0.0.1 --port 8791` and ONE consumer with `python -m mobius.worker.runner`,
using explicit tracked process IDs and a bounded parent supervisor. Set a real
fixed consumer ID for this run. Do not reuse an existing production queue. A
worker process may continue polling after the canary ends, so stop it at the
parent supervisor deadline and on all exit paths. Retain logs privately until
the authorized evidence audience is settled. No automated cleanup deletion is
authorized by this recipe.

## Explicit canary invocation after authorization

`python scripts/three_worker_canary.py --api http://127.0.0.1:8791 --expect-worker-id <exact-configured-consumer-id> --execute-local-canary`

The flag is an acknowledgement, NOT a grant. This creates application,
authorization and investigation test records through the API. The synthetic
record is labelled as a test record and is not the owner's permission. The
client uploads fixed deterministic binary AXML plus the existing real DEX,
then enqueues/waits/applies API kinds `recon`, `provider-analysis` and `spectre`
(DEX) in that order, requiring the exact configured worker ID on all three.
No fake completion, direct DB result edits or inline route is used.

All API work shares a 900-second deadline and the reused bounded HTTP transport.
The consumer's own provider/DEX budgets can exceed that deadline; therefore the
caller deadline is NOT consumer cancellation. The parent supervisor must stop
owned processes after a real execution is authorized, recording interrupted job
state honestly. A stopped/misconfigured consumer must leave the client failed or
timed out, never a green skip or inline fallback.

## Evidence and limits

The report contains exact fixture digest, scan/job/worker IDs and successful apply
checks. API apply routes perform the existing staged-input/output hash/schema
checks. Worker identity/status fields alone are not independent proof of kernel
isolation. Run and retain the existing OCI mount probe separately on that same
host, and separately verify any stronger network/resource claims.

The existing canary DEX has no provider-flow class. An empty provider exposure
set is expected. A pass proves the three-worker API/queue plumbing for this
fixture, NOT provider-flow semantics, model evidence richness, model success,
Android identity, typed test execution or full-agent readiness. The richer
code-bearing fixture and the real model-to-security-test/report journey remain
separate work. Do not seed flows or force hypotheses to turn this canary green.

Before any broader run: reconcile exact target and evidence audience, verify
host/image provenance and resource bounds, choose a reviewed code-bearing lab
contract, and get the required runtime confirmation. This recipe does none of
those by itself.

## Explicit disposable-instance freshness seam, separately reviewed source

Default API exposes neither an application list nor this test seam. An explicit
factory `mobius.api.canary_app:create_canary_app` is available only with
`MOBIUS_ENV=test`, disabled model gateway, a canonical `MOBIUS_CANARY_RUN_ID`
UUID and literal `MOBIUS_CANARY_WORKER_ID`. The manual workflow must generate a
fresh run UUID and set the same values for the factory and canary client. Add
`--expect-run-id <same-run-UUID>` to the explicit invocation. Factory startup
refuses nonempty investigation/application/authorization/job/evidence/hypothesis/
approval/report/PoC tables. Its hidden GET `/_canary/freshness` repeats that check
and returns only run ID, configured worker ID and an empty flag, never user data.
The client refuses missing/mismatched fields before upload. Default API returns
404 and the client makes no non-GET request.

This is a freshness HEURISTIC and configuration correlation, not cryptographic
attestation or worker authenticity. A malicious local service could forge it,
and the empty check races with another writer. Exclusive disposable host/DB
ownership and no tunnel to a real instance are deployment duties. The API kind
names `recon`, `provider-analysis`, `spectre` match existing job routes. Exact
worker ID proves configuration agreement, not that the worker was isolated.

The synthetic authorization is a product test record, not owner permission.
The client has no model-consent/hypothesis/PoC/approvals/report requests. Static
services check digest/package/intensity/expiry, not human legal authority.
Docker access for the consumer is root-equivalent; use a disposable host only.
Before runtime, independently verify network denial and CPU/memory/disk/output/
time enforcement. Offline tests do not establish those kernel-enforced limits.
