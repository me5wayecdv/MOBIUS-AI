# HELD concrete owned-APK boundary and review contract

This replaces an unrestricted-emulator shortcut with a concrete source target.
No build/SDK install/emulator/ADB/app/network execution is authorized by this
file, and no harness is claimed ready. Review must resolve the remaining closure
and product registration before any activation. Source flags remain FALSE.

## Boundary, required topology

One fresh anonymous net+mount+PID namespace and private chroot encloses ALL of:
owned proxy/origin, emulator/QEMU/slirp, one adb server/client, app-build tools,
product API test driver and evidence collector. No veth, bridge, host network
namespace, default route or inherited host socket is attached. Only private
loopback is brought up. Emulator's guest network may exist internally, but its
slirp/QEMU outer sockets remain in this no-uplink namespace, not the runner's
network. Host10.0.2.2 connectivity is not granted; use explicit adb reverse.

The only planned host device delegation is /dev/kvm, exact character device
identity recorded, bound into the private root for the reviewed emulator. That
is a kernel-device trust dependency, not proof of hostile-emulator isolation.
Software rendering only, no host GPU/audio/webcam/microphone/smartcard or USB
passthrough. Device access and /proc/FD namespace evidence must be reviewed.

Read-only binds: exact hash-manifested SDK closure, runtime/toolchain, product
source/dependencies and required host libraries; fixed individual /dev/null,
/dev/urandom,/dev/random,/dev/kvm only. Fresh proc mounted for private PIDns,
fresh tmpfs /tmp,/run,/dev/shm; private home/AVD state in exact owned output.
No host /home,/root,/run,/var,/tmp,/sys, docker socket, credential path or broad
/dev bind. Main supervisor closes descriptors except stdin/out/err before child
exec and drops all capability sets, supplementary groups and sets no-new-privs.
The app and emulator operate as the owned fixture UID, not privileged host root.

One private adb server uses tcp:127.0.0.1:5037 inside the same namespace, clean
HOME/private server keys, no connection to host adb5037 or external device. Fixed
emulator serial emulator-5554, console/adb ports5554/5555, no gRPC interface,
no snapshots/quickboot load/save, no camera/audio/Bluetooth, no credential import.
Exact emulator flags need validation against the pinned binary without starting
it first, then source review. No guessed unsupported CLI option is execution.

`adb reverse tcp:18080 tcp:18080` is the sole authorized local broker mapping.
Record list before/after; refuse pre-existing mapping, create fixed pair, verify
it, remove it in bounded cleanup and independently re-read absence. Both server
and emulator are inside the same private namespace, so reverse cannot bridge
to runner-host sockets. No forward, port0 wildcard, host shell service, arbitrary
ADB serial/script or device import is supported by the profile.

## Stages and budgets

A. Public toolchain archive retrieval, hash+size+path verification only, no SDK
code execution. Official package metadata sources are recorded in
`toolchain-candidates.json`; it is NOT a resolved executable lock. Pin all actual
SHA256s, JDK and library closure first. Network retrieval ends before runtime
namespace creation. Installing SDK/license acceptance is separately reviewable.

B. Namespace setup/boot provisioning with explicit separate ceiling. This is
fixture infrastructure only: never launch the owned app or send test traffic
while waiting for plan approval. Runtime proof must show guest boot, package
absence, owned adb server/emulator identity, no host socket inheritance, private
netns topology and clean reverse list before accepting a ready state.

C. Generate run-local origin key/cert and proxy key/CA, owned endpoints only.
Embed only public proxy CA DER in APK, record CA digest. The app-only raw-socket
KeyStore plus HTTPS endpoint ID preserves verification. No user/system CA edits
or pinning bypass. Source has no bundled placeholder CA that could accidentally
be trusted on another run. App build requires this exact public file.

D. Offline build with fixed aapt2/javac/d8/zipalign/apksigner commands, no Gradle
plugin/dependency resolution. Compile the owned source only. Package/SDK/
manifest/source/certificate/APK/signature digests recorded before install. Build
signing key is disposable, never a user's key, destroyed during sanitation.
Actual build is held; Java source/XML text is not a successful compilation.

E. Ordinary product API authorization/approval must bind newly built APK digest,
new owned-APK traffic profile and fixed endpoints. Profile is deliberately NOT
`native_local_fixture`: that identity says no APK traffic. `profile.py` is pure
unregistered preparation, not a product action. No old stdlib/emulator grant can
be transferred. A typed profile/action/readback/report change needs exact review.

F. After committed prelaunch authority check, run at most60s: install verified
APK, fixed reverse mapping, explicit activity launch with nonce, retain guest
UID/PID/package/digest/log record, capture one native original from actual app
socket, replay that captured request once, second independent origin receipt,
stop producers, verify exact counts/canonical/hash/receipt binding. No stdlib
request can satisfy app-origin success. Fresh posthost authority and exact total
output-before-write guards still apply. If boot/build overhead cannot fit, do
not silently extend cap or move unauthorized app traffic into provisioning.

G.60s teardown+10s collection reserve, plus independent workflow sanitizer after
outer timeout/cancel. Force-stop/uninstall only exact owned package, remove exact
reverse, stop owned emulator/adb, identity-scoped proxy/origin termination,
private keys/home/AVD/jail destruction. Missing launch/process/namespace records
are UNVERIFIED, never proof of absence. Read-only independent final check and
bounded allowlisted recovery must retain actual failures and partial originals.

## Acceptance matrix, no shortcuts

- Actual APK digest/package/signature/public CA equals approved fixed source.
- Emulator/adb/proxy/origin and app launch identity, runtime privilege/FD/network
  facts retained, not only root pre-drop command descriptions or counters.
- One app-origin request logged under nonce and observed app process identity;
  original native bytes parsed independently, actual request replay sameflow,
  two distinct origin receipts, four canonical requests equal, no extra receipt.
- New product profile makes APK the traffic source, not merely authorization
  anchor. Exact case/auth/plan/approval/run/objects/report/hash relationships.
- App untrusted-proxy CA negative, hostname mismatch and untrusted-origin chain
  negatives must preserve verification and no unexpected origin receipt. Keep
  every control's own isolated nonce/ledger/process context, not weakened positive
  config. Pinning posture is outside this owned test-app demonstration.
- Normal path plus reviewed no-native lifecycle fault tests before a separate
  bounded actual failure/cancel experiment; do not run more scenarios by default.

## Remaining implementation blockers

Resolved metadata lock and JDK/runtime closure; actual wrapper with reviewed
KVM+chroot+emulator/adb lifecycle; offline build driver; product typed owned-APK
registration; app/host attribution and negative-control driver; independent
recovery/checker. These are stated gaps, not executable pseudocode. No workflow
is registered for this directory. Do not invoke an unrestricted existing CI
emulator as a shortcut. No model, third-party target, production action, image
publication or paid resource is part of this preparation.
