# PHANTOM dynamic feasibility (bounded, free, safe routes)

Status of the ANDROID_SECURITY_METHODOLOGY.md section 7 prerequisites against
what is now verified infrastructure, and what remains a real limit. Every
claim here is either CI-verified (run-referenced) or source-grounded
(URL-referenced); unverified items say so.

## Prerequisites: then vs now

| Requirement (methodology §7) | Status |
|---|---|
| Hardware acceleration | **Satisfied (CI-verified).** KVM on `ubuntu-latest` via the udev rule; three emulator runs completed (44834324180, 44842949369, and the #102 hardened smoke run). |
| Root / frida-server | **Route exists (source-grounded, not yet CI-verified).** Non-Google-Play emulator images are userdebug builds where `adb root` works; `frida-server` is a standalone binary pushed to the device. Sources: https://frida.re/docs/android/ , https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0001/ , https://stackoverflow.com/questions/43923996/adb-root-is-not-working-on-emulator-cannot-run-as-root-in-production-builds |
| Emulator detection | Expected and recorded, never hidden; AOSP images are trivially detected. A detected instrumentation attempt is itself defensive-posture evidence. |
| Certificate pinning | Per-app; bypass is a moving target and out of bounded scope. Whether the pinned Allsafe lab build pins is **unverified** (a runtime question, not asserted here). |
| Play Integrity | **Hard limit.** Cannot pass on an emulator; apps gated by it refuse to run. Lab target unaffected. |
| Isolation | **Partial.** Ephemeral GitHub runner has no LAN bridge (lateral isolation holds), but job internet egress cannot be disabled on the free route (the job must download the APK and tooling). Acceptable for the public lab target; a real limit for anything else. |
| Snapshotting / lifecycle | Cold boot per investigation is the de-facto CI posture (ephemeral runner, `disable-animations`, no saved state). Mobius-managed AVD lifecycle (driving `avdmanager`/`emulator` directly instead of the action, snapshot-per-investigation) is feasible on the same free KVM route; **not implemented**. |

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

- Frida route: source-grounded but not runtime-verified on this CI emulator
  image (adb root on the exact `default` API-29 image is expected, not
  observed).
- Instrumentation gating decision (above).
- Allsafe pinning posture: unverified.
- Mobius-managed emulator lifecycle: feasible, unimplemented.
- Full network isolation: unavailable on free hosted runners.
