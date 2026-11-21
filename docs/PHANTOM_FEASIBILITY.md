# PHANTOM dynamic feasibility (bounded, free, safe routes)

Status of the ANDROID_SECURITY_METHODOLOGY.md section 7 prerequisites against
what is now verified infrastructure, and what remains a real limit. Every
claim here is either CI-verified (run-referenced) or source-grounded
(URL-referenced); unverified items say so.

## Prerequisites: then vs now

| Requirement (methodology §7) | Status |
|---|---|
| Hardware acceleration | **Satisfied (CI-verified).** KVM on `ubuntu-latest` via the udev rule; three emulator runs completed (44834324180, 44842949369, and the #102 hardened smoke run). |
| Root / frida-server | **Satisfied (CI-verified).** `adb root`, pinned frida-server 17.27.4 push/start/answer, and observation-only class enumeration (11361 classes on the pinned Allsafe lab build) all completed on the CI emulator: run 44855421235 (32050e6) and post-merge run 44857880298 (93aa0b7). Mobius now owns the lifecycle: `scripts/phantom_emulator_lifecycle.py` verifies the binary against the pinned uncompressed sha256 before any device traffic. |
| Emulator detection | Expected and recorded, never hidden; AOSP images are trivially detected. A detected instrumentation attempt is itself defensive-posture evidence. |
| Certificate pinning | Per-app; bypass is a moving target and out of bounded scope. Whether the pinned Allsafe lab build pins is **unverified** (a runtime question, not asserted here). |
| Play Integrity | **Hard limit.** Cannot pass on an emulator; apps gated by it refuse to run. Lab target unaffected. |
| Isolation | **Partial.** Ephemeral GitHub runner has no LAN bridge (lateral isolation holds), but job internet egress cannot be disabled on the free route (the job must download the APK and tooling). Acceptable for the public lab target; a real limit for anything else. |
| Snapshotting / lifecycle | Cold boot per investigation remains the de-facto CI posture. Mobius-managed pieces are **implemented**: bounded boot verification and the pinned frida-server lifecycle (above). AVD creation is still action-managed; driving `avdmanager`/`emulator` directly or snapshot-per-investigation remains **not implemented**. |

## Bounded instrumentation route (Frida-class)

A free route exists and stays inside the established safety posture:

1. CI installs the Frida CLI (pip, **CI job tooling only** - not a repo
   dependency; the repo's runtime code stays dependency-free).
2. Download the matching `frida-server` android-x86_64 binary from the
   project's GitHub releases (pinned version + sha256, like the APK).
3. `adb root` on the non-Play emulator image, push and start frida-server
   inside the ephemeral emulator only.
4. First slice is observation-only: attach to the lab app and enumerate
   (loaded classes/modules), no method tampering, no bypass scripts.

**Gating (resolved):** instrumentation probes use the existing
`non_destructive` safety class - the approval gate (`requires_approval` +
granted approval via the PoC approvals API) plus a mandatory
`stop_emulator_instrumentation` cleanup step. `read_only` is not stretched:
it remains free of any process attachment.

## Bounded traffic-capture route (mitmproxy-class)

Source-grounded (official docs:
https://docs.mitmproxy.org/stable/howto/install-system-trusted-ca-android/):
the mitmproxy CA goes into the system store on an emulator booted with
`-writable-system`, via `adb root` + `avbctl disable-verification` + remount,
hashed-name install under `/system/etc/security/cacerts/`. Limits: apps can
ignore the system store (pinning), the writable-system route does not work on
Google Play images (Magisk route excluded as too many moving parts), and this
has not been CI-verified.

## What remains genuinely open

- Allsafe pinning posture: unverified.
- Mobius-managed AVD creation (avdmanager/emulator direct, snapshotting):
  feasible, unimplemented; AVD creation is action-managed today.
- Full network isolation: unavailable on free hosted runners.
