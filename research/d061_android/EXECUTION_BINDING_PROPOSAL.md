# Minimal execution / source / private-output binding and teardown proposal

STATUS: PROPOSAL ONLY. Nothing registered, dispatched or executed. Creates no grant.
Scope: F1 plus one natural F2 (host_primitive_probe), then optional package-hash inspection.

## 1. Documented guarantee vs observable proof

| Claim | Basis | Class |
|---|---|---|
| Each standard GitHub-hosted Linux runner (multi-CPU) is a new VM hosted by GitHub | https://docs.github.com/en/actions/reference/runners/github-hosted-runners ("each GitHub-hosted runner is a new virtual machine (VM) hosted by GitHub", excl. single-CPU) | Documented provider guarantee |
| The VM is automatically decommissioned when the job finishes | Reviewer read https://docs.github.com/en/actions/how-tos/manage-runners/github-hosted-runners/use-github-hosted-runners (I could not reproduce the sentence with my own text search of that page; carried as reviewer-read) | Documented provider lifecycle; no per-run attestation, no timing guarantee |
| Passwordless sudo, so root-only primitives are reachable | same page | Documented |
| Public repo standard runners are free | same page | Documented |
| Teardown happened | Nothing a job can observe: the job cannot witness its own VM's destruction | Irreducible: no in-job proof |
| Workflow artifacts and logs persist 90 days by default, deletable by write-access users | https://docs.github.com/en/actions/how-tos/manage-workflow-runs/download-workflow-artifacts , .../remove-workflow-artifacts | Documented |

Consequence: "VM destroyed" may be stated only as "provider-documented new VM per job; destruction not independently observable". The probe's in-job cleanup (pidfd-held owner, identity-bound leaf, unbound = UNVERIFIED) is the only observable cleanup and covers only resources the attempt created. It is not teardown proof.

## 2. Independently owned teardown

Candidate owner: GitHub runner VM lifecycle (provider), not the probe. Required owner properties and status:
- Independent of the live probe owner: YES (provider lifecycle) per docs "new VM"; destruction semantics UNVERIFIED.
- Outer observer: a separate later job or the PR reviewer can observe only (a) job conclusion, (b) the uploaded envelope, (c) absence of a still-running job. Not VM state.
- CORRECTION: a self-owned host is NOT needed merely because destruction is not self-observable. Basis: provider decommissioning + 10-minute timeout (bounds intended lifetime, not destruction time) + live-owner leaf/child cleanup. A failed in-job cleanup stays False/UNVERIFIED and is never retroactively passed because decommissioning is expected.
- Irreducible: no in-job destruction receipt and no timing attestation.
- Leaked-state bound: probe uses only a leaf cgroup under a parent it anchored, a sleep child, no network, no secrets, no SDK/APK. Worst case of failed cleanup is an idle sleep in a VM the provider recycles.

## 3. Source binding (entrypoint)

- Workflow file to be created later, NOT now, on this branch only: workflow_dispatch only, no push/pull_request trigger, `permissions: contents: read`, single job, `runs-on: ubuntu-24.04` (pin label; re-verify at review), `timeout-minutes: 10`, no secrets, no `actions/cache`.
- Checkout `ref` pinned to an exact 40-hex SHA input, verified equal to `git rev-parse HEAD` and written to the envelope as source_commit. Reviewer approves that exact SHA of the workflow file before any dispatch.
- Entry: `python research/d061_android/host_primitive_probe.py` with APPROVED_FOR_EXECUTION flipped only in a reviewed commit; envelope must carry run_id, source_commit, sleep_sha256, probe, pidns_claim (audience_gate host_primitive_result class).
- Labels: run name carries the SHA; no user data.
- Registration of a workflow file is itself the held action. Dispatch needs main's evidence clearance.

## 3a. Private-output binding

- Single seam: audience_gate.publish_private. Destination must be opened by open_private_destination (anchored dir, owned temp, inode-bound link).
- CORRECTION: the conclusion below is too broad. Verified: public MOBIUS-AI logs/artifacts are outsider-readable, so they are not private sinks, and a runner-local owner-only file is private only while the VM lives (not retrievable). NOT established: any private retained route. Private repos exist on the connected account but using one needs route-specific access, credential, cost and audience authority and is not assumed. An encrypted-ciphertext upload would be a separately reviewed design, not an existing route. The exact missing seam is a retained, access-restricted retrieval path.
- Original text, superseded where it conflicts: on a GitHub runner the only retained sinks are job logs and artifacts. In a public repo both are reachable by outsiders (logs public; artifact download to GitHub-authenticated users: treat as public, to be confirmed by reviewer). So a PRIVATE route does not exist on free CI. UNRESOLVED.
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

## 6. Held entrypoint and workflow source (added)
- host_primitive_entry.py: separate entrypoint. Refuses unless APPROVED_FOR_EXECUTION is True in entry, probe and gate (reviewed commit only). Measures a clean checkout HEAD (fixed /usr/bin/git, empty env) and compares to --expected-commit as a cross-check, never a grant. Measures ImageOS/ImageVersion into the envelope as an observed label (not an attestation). Output only under RUNNER_TEMP via publish_private. Prints nothing; closed exit codes 0/1/2/3. Ops are closed on every path.
- held/host-primitive-probe.workflow.yml.txt: deliberately outside .github/workflows (not registered). No dispatch parameters, permissions {}, checkout pinned to actions/checkout 11bd71901bbe5b1630ceea73d27597364c9af683 (v4.2.2 tag resolves to this commit via api.github.com/repos/actions/checkout/git/ref/tags/v4.2.2) with persist-credentials false, no upload step. Placeholders (reviewed probe commit, cgroup parent, route evidence id) fail closed.
- Claim distinctions kept: no intentional workload network is not network isolation; permissions {} is not a credential-free VM (Actions orchestration uses its own credentials); timeout is not provider teardown timing; ubuntu-24.04 is an OS label, not an immutable image; sleep sha256 is measured on the VM, not a reviewed pin.
- Unresolved bindings: delegated cgroup2 parent on the runner, retained private retrieval route, audience authority for any retained or public signal, real-kernel behavior. Package inspection stays separate from this probe.
