# HELD provisioning-to-approval handoff

This is the chosen source design, not a completed implementation or approval.
The old native_local_fixture profile cannot be reused: its target APK was only
an authorization anchor and its traffic was explicitly stdlib, not Android.

## One namespace, two clocks, no traffic during provisioning

The immutable closure must contain the product API/test driver, DB dependencies,
Android tools, native capture runtime and all executable/library dependencies.
They run inside the same fresh no-uplink namespace. No API or ADB socket points
outward. The disposable product DB/store live under /work, never a production DB.

Provisioning has a separate fixed ceiling, provisionally 240 seconds: create
fresh private AVD, boot to recorded readiness, generate owned origin key/cert,
start owned origin/proxy without sending an application request, parse the proxy
public CA DER, build/sign/check the owned APK and retain its digest/signature.
No application is installed or launched and no positive/control traffic occurs
in this phase. Zero native original and zero origin receipts are mandatory.
Certificate generation/build must not be triggered by a supposedly approved
plan whose APK digest is still unknown. Boot and build costs cannot be hidden
inside or silently added to the 60-second approved operation.

With the resulting exact APK/public-CA bytes, the contained fixture API then
uploads that APK, creates a fresh owned-test authorization/case and requests and
grants the exact proposed typed owned-APK plan as an explicitly disposable test
actor. This is product integration setup, not the owner's personal approval or
an authorization to run the harness. Any historical genuine model content stays
an unchanged attributed fixture import. Allsafe claims are not findings about
the owned app, and no new model generation is allowed or needed.

The product host seam must use the already provisioned in-namespace processes,
never start a second host-network emulator or reuse a host ADB server. A fresh
committed product authority read checks the actual APK/profile/plan at launch.
Then at most 60 seconds covers exact APK install, fixed reverse creation, app
prepare, observed UID/PID/command, one same-process commit, actual native
original capture/replay and independent backend receipts. Fresh posthost
authority, exact evidence budgeting before blob writes, persisted readback and
report generation remain required. Separate 60-second teardown and 10-second
collection reserve are not operation time. Expired approvals are not renewed
implicitly, and provisioning failure is not retried into success.

## Source state, 2026-11-21

Implemented source, held and unexecuted: owned Java/XML, fixed prepare/commit,
app-only CA verification and HTTPS endpoint ID; offline build/sign/check driver;
fixed private ADB helper; exact-copy namespace supervisor with no broad host
filesystem mounts; fixed emulator/ADB boot/listener/leader teardown helper;
archive-byte member hashing. Eight static/pure tests pass. Full Python suite
passed with its normal skips. No Java compilation, SDK binary execution,
namespace/KVM/emulator boot, APK install/launch or traffic experiment occurred.

Still missing before an activation review:

- Resolved staged runtime/loader/library closure. The six archive hashes and
  member inventory digests do not replace it. Links need confined resolution.
  SDK license acceptance and safe staging must be reviewed before installation.
- Exact pinned emulator option/listener behavior, including whether default
  gRPC is absent. Current listener guard rejects an extra listener. It does not
  invent a disable flag or assume localhost means permitted. Guest /proc and
  ADB reverse output behavior also require actual pinned verification.
- A complete contained_driver.py performing the sequencing above. The wrapper
  requires that exact path in the closure but it does not exist yet, so an honest
  closure cannot be created. This is a deliberate fail-closed missing dependency.
- Typed product schema/action/adapter, injection, evidence validation/persistence,
  exact fresh approval flow and readback/report journey for APK-origin identity.
- App socket-to-UID/PID/nonce correlation and independent capture projection,
  separate app-untrusted-proxy, hostname and untrusted-origin controls.
- Independent outer stage-aware absence/sanitation/recovery, fault tests and
  final evidence allowlist. Root-owned wrapper records must remain outside the
  fixture-writable /work subtree. Missing process/namespace records stay unverified.

No Android workflow is registered. Every new execution/build flag is FALSE.
PR preparation is not a successful Android experiment or project completion.
