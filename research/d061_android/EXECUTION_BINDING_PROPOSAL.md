# Minimal execution / source / private-output binding and teardown proposal (consolidated)

STATUS: PROPOSAL ONLY. Nothing registered, dispatched, executed or published. Creates no grant.
Mechanical APPROVED_FOR_EXECUTION flags are necessary gates, never user or legal authority.
Scope: F1 plus one natural F2 (host_primitive_probe). Package inspection is separate and not covered.

## 1. Teardown: documented vs observable
- Documented (provider): each standard multi-CPU GitHub-hosted runner is a new VM per job
  (https://docs.github.com/en/actions/reference/runners/github-hosted-runners), and the VM is automatically
  decommissioned when the job finishes (https://docs.github.com/en/actions/how-tos/manage-runners/github-hosted-runners/use-github-hosted-runners).
  Provenance: the independent reviewer fetched that live official page directly (most recently 14:07:27 Cairo, 2026-11-21).
  I did not reproduce the sentence with my own text search, and main did not independently re-fetch it. Provider
  documentation, not a per-run timing or attestation.
- Not provided: an in-job destruction receipt, a per-run attestation, or timing of decommissioning.
  The 10-minute job timeout bounds the intended job lifetime, not teardown time.
- Basis for a benign sleep-only probe: provider decommissioning (independent lifecycle) + job timeout +
  live-owner leaf/child cleanup. No self-owned host is needed merely because destruction is not self-observable.
- A failed in-job cleanup stays False/UNVERIFIED and is never passed retroactively on the expectation of decommissioning.

## 2. Source binding (host_primitive_entry.py)
- Workflow template: held/host-primitive-probe.workflow.yml.txt, outside .github/workflows (not registered).
  No dispatch parameters, permissions {}, checkout pinned to actions/checkout 11bd71901bbe5b1630ceea73d27597364c9af683
  (v4.2.2) with persist-credentials false, no upload step, no global git bypass.
- The workspace is chowned root:root and go-w before the root run, so root git needs no safe.directory bypass and
  the tree is not runner-writable after measurement. On a runner with passwordless sudo this protects provenance and
  accidents, not against a malicious sudoer. The post-step tolerance of the ownership flip is unverified.
- Entry measures HEAD (fixed /usr/bin/git, empty env, clean tree) and cross-checks it against the expected commit.
  It must live at <repo>/research/d061_android of the same resolved repo. Repo/dirs/modules must be trusted-owned,
  non-symlink, not group/other-writable. Each of entry, probe and gate has its git blob id computed from the bytes
  read and compared with `git rev-parse HEAD:<path>`. Probe and gate are executed from those same bytes, not imported
  by name. The entry's own bytes are checked but it is already running (best-effort).
- Envelope fields source_commit and runner_image are measured by the entry. Sleep sha256 is measured on the VM
  and recorded, not a reviewed pin. ubuntu-24.04 is an OS label, not an immutable image.

## 3. Output
- The entry creates its own destination /run/d061-hp-<run_id> (exclusive mkdir 0700, root-owned parent) and writes
  only through publish_private. No caller-supplied destination exists. The file vanishes with the VM: NOT a retained or
  retrievable route.
- Private retained retrieval route: NOT established. Public MOBIUS-AI logs and artifacts are outsider-readable and not
  private. Private repositories exist on the connected account but are unused: using one needs route-specific access,
  credential, cost and audience authority. An encrypted-ciphertext upload would be a separately reviewed design.
  Missing seam: a retained, access-restricted retrieval path.
- No public fallback. A result never committed is dropped (exit 3). A committed result is never dropped, and
  incomplete publication flags (temp removal, temp/dir close, dir fsync) give exit 4, not success.
- Exit codes 0/1/2/3/4, the job conclusion, logs and any PR comment are signals whose audience is unresolved. Any
  public verdict, retained log or hash comment is a new disclosure needing applicable audience authority.
  Deleting this probe's own temporary outputs is execution cleanup; it does not undo a disclosure.

## 4. Public log paths
- Entry code wraps argument parsing, source binding, run and publication in one catch with no traceback, and exits via
  os._exit. That does NOT cover Python parse/startup or top-level imports of the entry file itself, which run before the
  catch, nor the git subprocess's own startup behavior.
- What the template does: stdout and stderr of the setup and entry processes are redirected to /dev/null. This contains
  those process streams only. NOT contained: the checkout action's own log lines, step names, the job conclusion and the
  exit-code distinctions, all outsider-readable in a public repo.
- Do not generalize the recursive workspace chown beyond this disposable job; never apply it to a persistent checkout.

## 5. Claim distinctions
- No intentional workload network (child env empty, no connection made), not network isolation.
- permissions {} is not a credential-free VM (Actions orchestration uses its own credentials).
- Timeout is not provider teardown timing.

## 6. Unresolved before any registration
Delegated cgroup2 parent on the runner; retained private retrieval route; audience authority for any retained or public
signal; real-kernel behavior of RealOps; runner image is only a dated label; user/legal authority for anything beyond
this internal source preparation.
