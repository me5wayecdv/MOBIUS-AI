# Minimal execution / source / private-output binding and teardown proposal

STATUS: PROPOSAL ONLY. Nothing registered, dispatched or executed. Creates no grant.
Scope: F1 plus one natural F2 (host_primitive_probe), then optional package-hash inspection.

## 1. Documented guarantee vs observable proof

| Claim | Basis | Class |
|---|---|---|
| Each standard GitHub-hosted Linux runner (multi-CPU) is a new VM hosted by GitHub | https://docs.github.com/en/actions/reference/runners/github-hosted-runners ("each GitHub-hosted runner is a new virtual machine (VM) hosted by GitHub", excl. single-CPU) | Documented provider guarantee |
| The VM is destroyed after the job | Not found as an explicit sentence in the pages fetched this session. Only "new VM" per job is read. | UNVERIFIED as a docs claim |
| Passwordless sudo, so root-only primitives are reachable | same page | Documented |
| Public repo standard runners are free | same page | Documented |
| Teardown happened | Nothing a job can observe: the job cannot witness its own VM's destruction | Irreducible: no in-job proof |
| Workflow artifacts and logs persist 90 days by default, deletable by write-access users | https://docs.github.com/en/actions/how-tos/manage-workflow-runs/download-workflow-artifacts , .../remove-workflow-artifacts | Documented |

Consequence: "VM destroyed" may be stated only as "provider-documented new VM per job; destruction not independently observable". The probe's in-job cleanup (pidfd-held owner, identity-bound leaf, unbound = UNVERIFIED) is the only observable cleanup and covers only resources the attempt created. It is not teardown proof.

## 2. Independently owned teardown

Candidate owner: GitHub runner VM lifecycle (provider), not the probe. Required owner properties and status:
- Independent of the live probe owner: YES (provider lifecycle) per docs "new VM"; destruction semantics UNVERIFIED.
- Outer observer: a separate later job or the PR reviewer can observe only (a) job conclusion, (b) the uploaded envelope, (c) absence of a still-running job. Not VM state.
- IRREDUCIBLE MISSING GUARANTEE: an observable, provider-attested statement that the VM and its cgroup/leaf are gone. Free CI cannot supply it. Accept as stated residual risk (resources are inside a per-job VM holding no secrets and no user data) or use a self-owned host (new account/spend: gated, not proposed).
- Leaked-state bound: probe uses only a leaf cgroup under a parent it anchored, a sleep child, no network, no secrets, no SDK/APK. Worst case of failed cleanup is an idle sleep in a VM the provider recycles.

## 3. Source binding (entrypoint)

- Workflow file to be created later, NOT now, on this branch only: workflow_dispatch only, no push/pull_request trigger, `permissions: contents: read`, single job, `runs-on: ubuntu-24.04` (pin label; re-verify at review), `timeout-minutes: 10`, no secrets, no `actions/cache`.
- Checkout `ref` pinned to an exact 40-hex SHA input, verified equal to `git rev-parse HEAD` and written to the envelope as source_commit. Reviewer approves that exact SHA of the workflow file before any dispatch.
- Entry: `python research/d061_android/host_primitive_probe.py` with APPROVED_FOR_EXECUTION flipped only in a reviewed commit; envelope must carry run_id, source_commit, sleep_sha256, probe, pidns_claim (audience_gate host_primitive_result class).
- Labels: run name carries the SHA; no user data.
- Registration of a workflow file is itself the held action. Dispatch needs main's evidence clearance.

## 3a. Private-output binding

- Single seam: audience_gate.publish_private. Destination must be opened by open_private_destination (anchored dir, owned temp, inode-bound link).
- On a GitHub runner the only retained sinks are job logs and artifacts. In a public repo both are reachable by outsiders (logs public; artifact download to GitHub-authenticated users: treat as public, to be confirmed by reviewer). So a PRIVATE route does not exist on free CI. UNRESOLVED.
- Minimum disclosure option: the envelope for host_primitive_result contains no paths, no package names, no user data: only pass/fail verdicts, run_id, SHA, hashes of own sleep binary, pidns_claim. Main/reviewer may decide this class is safe for public log. Package inventories (member paths) must NOT go to the public log: held until a private sink exists.
- Retention owner: workflow-run deleter = repo write-access holder (documented deletion route). Proposed: delete the run's artifacts after the reviewer records the envelope hash in the PR; 90-day default otherwise. Deletion of old data is gated: needs main.

## 4. Minimal run sequence (when cleared, not now)
1. Reviewer approves workflow SHA and probe SHA.
2. Dispatch once on the pinned SHA. No retries.
3. Job writes envelope through publish_private to a runner-local dir, prints only the verdict envelope (public-safe class).
4. Reviewer checks envelope SHA == reviewed SHA, fields valid, validate_content passes.
5. Result claim is limited to: F1+F2 primitive behavior on that runner image on that date. Not SDK, APK, Android, or teardown proof.

## 5. Open decisions (not user questions)
- Main: accept "provider-documented new VM, unobservable destruction" as the teardown basis, or hold.
- Main: public-log-safe class for host_primitive_result, yes/no.
- Main: workflow registration and dispatch clearance.
- Legal/license items remain as in INTERFACE_SPEC section E.
