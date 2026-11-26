# Tiny-image engine validation plan, HELD, source only

This is a plan, not a workflow or an approval. No command in it has been run. It does not exercise Android, SDK/JDK, KVM, ADB, APKs, native code or models. It cannot establish Android readiness.

## Entry gates, all required before planning an actual run

- Separate execution and disclosure authority, reviewed exact source SHA and independent safety clearance. Earlier one-run capability-test permission is spent and does not cover this plan. No default public workflow, run result, log or artifact.
- A disposable whole VM with an enforced disk/memory/CPU/time budget covering both the Docker daemon and its export staging, not merely the CLI output file. The daemon-side guard is not implemented. Real DockerCli.save therefore refuses by default. Do not pass a no-op guard to make it run.
- Two already-present, non-SDK, independently digest-pinned and image-ID-bound tiny role images. Exact IDs/digests and locks are unresolved; no plausible placeholder is a usable pin. Obtaining/building/pulling images is not part of this plan's authority. A changed tag is not a pin. Their combined expanded/export footprint must fit an independently checked small budget, for example at most 32 MiB per image within a 256 MiB daemon-export budget.
- Independent per-role typed filesystem locks and source manifest. Both images contain only the fixed gate, a benign writer/reader and its small interpreter/runtime closure. No SDK, emulator, adb, shell-selected command, user data, credentials, host socket or image-declared volume. Distinct actual image IDs, not merely distinct registry names.
- A separately reviewed INERT spec, not the Android runtime default: no device mappings, KVM gid, privileged mode or host namespaces; network none, caps dropped, read-only rootfs, UID 65534, explicit command/env, bounded tmpfs/work and pids/ulimits. The Android create_argv currently requires KVM for runtime and must NOT be used unchanged for this check. No spec fallback on engine mismatch.
- Approved evidence audience and supported private retention/delivery route. Neither exists merely because the repository is public. No artifacts uploaded by default.

## Single bounded positive attempt

Before either container exists, verify both image records and final-filesystem inventories against the independent locks. Use private client scratch on a fixed-size tmpfs, including hidden CLI temp files; daemon scratch has its independent whole-VM bound. Stop on any mismatch or budget error. Do not export an SDK-sized image using this plan.

Set one absolute short live deadline, proposed 30 seconds from first create through absence, with a separate at-most-10-second exact-resource emergency cleanup allowance. Each command gets only the remaining time, capped at one second for inspect; pump at most 64 KiB per tick and resume on the next tick. Preverification is outside the live phase and has its own absolute time and resource budget, proposed 20 seconds for known tiny images. Exact budgets require review against the selected VM and image facts before a run.

For each exact owned ID: persist create intent and returned ID, validate inspect normalization, start attached behind the gate, acquire bracketed process identity and held pidfd/ns/cgroup handles, compare complete host/sibling namespaces, persist identity and only then release. The benign writer puts one fixed bounded marker in /work. The owner then adds one fixed marker to the role's read-only /control inbox; the benign reader checks that later write is visible while it still cannot write /control. Neither role sees the sibling's work or inbox.

The payload exits. Confirm daemon exit plus held-process exit before normal removal. Close namespace handles before global membership/handle scan, preserve the cgroup fd through population/removal checks, then close it. Independently check exact ID not-found, cgroup empty/gone and namespace members/handles absent, with unreadable entries remaining UNVERIFIED. Keep role-specific absence distinct. Output only records actually acquired, never fixture booleans as engine evidence.

Stop without retry on API normalization mismatch, blocked mount, device requirement, deadline, unreadable identity, engine challenge or partial cleanup. No broad mount, host namespace, writable-rootfs or privilege fallback.

## Negative attempt, excluded unless separately included in approved scope

At most one held-gate-timeout OR attach-loss case, selected in advance. It is an additional case, not silently added to a positive-run approval. An attach-client death is not workload exit: the live owner retains identity, signals only within its approved cleanup scope, and proves the real exit/absence or records UNVERIFIED. Owner-death recovery is not tested or inferred.

## Emergency removal policy, source proposal only

Normal live kill requires a matching retained process identity. Emergency force removal by a full ID returned by THIS attempt's successful create is a different effect, intended only for an approved exact-resource cleanup scope. Never target a name, guessed ID or discovered container. Every such removal is marked emergency and UNVERIFIED; it cannot supply verified driver exit or verified absence. The code records this difference. Review and execution authority must cover it before activation.

## What a successful attempt could establish

Only the selected engine/CLI versions' inspect normalization, gate/stdin and later read-only-inbox behavior, bounded pumping, actual process/ns/cgroup acquisition, exit and exact absence for these tiny images on this VM. Not SDK installation/licensing, Android functionality, emulator compatibility, noexec on Docker bind mounts, owner-death recovery, production safety or portable provider support.
