# HELD actual owned Android test-app preparation

No APK has been built, installed or run. This source is not an authorization
flag and cannot grant runtime permission. It is the next original-scope slice,
not another stdlib traffic demonstration or an Allsafe capability claim.

## Smallest proposed actual app action

The owned test-only package org.mobius.ownedfixture performs one empty-body GET
with the fixed reviewed canonical wire contract from its own Android process.
Only the32hex run nonce is an input. The app contacts127.0.0.1:18080, CONNECTs
only127.0.0.1:18443, then sends the fixed request through verified TLS. A bounded
response status/body/nonce is checked. No arbitrary URL, redirects, credentials,
user data or external destination. Actual native addon replay must consume the
app-originated saved request and receive a second independent backend receipt.

Explicit trust: the APK must bundle only this run's public proxy CA certificate
as res/raw/fixture_proxy_ca. No private key enters the APK. Network security
config allows only that anchor and disables cleartext. The raw TLS socket uses
its own equivalent app-only KeyStore and HTTPS endpoint identification, with
no system/user CA modification or trust-all verifier. This is intentional
owned-app trust, not bypassing another app's certificate pinning.

## Required contained harness, not implemented or approved yet

- Fresh disposable emulator whose emulator/adb/brokers live within the reviewed
  no-uplink boundary. Merely reusing an unrestricted CI emulator is not enough.
- Exactly one adb reverse mapping tcp:18080 to the owned proxy in that boundary,
  created/verified/removed under recorded identities. This is an explicit local
  broker path to inspect, not universal containment inferred from counters.
- Fixed local TLS origin/proxy isolated from unrelated sockets, clean process
  environment/FDs, explicit CA generation/hash/cert-only APK embedding.
- Pinned Android platform/build-tools/JDK/toolchain and digest/signing evidence;
  compile and verify APK package/debug/test-only manifest/public CA bytes before
  install. No binary/prebuilt payload from unknown origin.
- Proof the network action came from installed owned APK process: package/APK
  hash/signature, observed process UID/PID/command/permissions, nonce and actual
  app launch/log status, native original+addon replay identity and independent
  receipts. Host stdlib client is not a substitute. Bind product auth/approval/
  plan/run/evidence/report provenance to the actual APK/traffic source explicitly.
- No inherited approval from stdlib-local profile. Existing profile explicitly
  excludes APK traffic. A separately reviewed typed profile/schema/harness is
  needed before execution. Do not silently reuse that identity or promise a run
  fits60seconds. Research the actual stage budget without executing it.
- Identity-scoped tracked teardown includes app stop/uninstall, adb reverse
  removal, emulator/adb shutdown, proxy/origin shutdown, keys/homes/jail cleanup,
  independent stage-required final absence and bounded recovery. No prefix kills.
- Client untrusted-proxy CA rejection must remain available as a control;
  hostname/untrusted-origin negatives and lifecycle failure paths remain gaps.

This directory supplies app source and scope only. Build/harness/runtime remain
held pending exact review. No third-party egress, system-CA changes, pinning
bypass, production activation, new model request or paid spend is implied.
