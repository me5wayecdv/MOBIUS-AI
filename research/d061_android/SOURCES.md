# Public source checks for held preparation, 2026-11-21

These sources establish documented semantics and candidate packages, not actual
compatibility/runtime results. Exact pinned binary behavior still needs its
separately reviewed toolchain verification. No build/emulator was run.

- https://dl.google.com/android/repository/repository2-3.xml
  Official stable package archive identities for platform35r2, build-tools35.0.0,
  platform-tools37.0.3 and stable emulator37.3.10. Preview emulator37.4.1 excluded.
  Metadata supplies SHA1/size, not a SHA256 closure. XML SHA256 kept
  with candidates. Package licenses require attention before installing.
- https://dl.google.com/android/repository/sys-img/android/sys-img2-3.xml
  Official default API29x86_64r8 image/size/SHA1.
  Five archive byte streams were retrieved and checked against exact official
  size/SHA1; local SHA256 values are recorded in toolchain-candidates.json.
  No ZIP was extracted or any downloaded binary executed.
- https://developer.android.com/privacy-and-security/security-config
  App custom anchors can be a raw PEM/DER resource, cleartext opt-out and
  restricted trust anchors are supported. Source uses only its public CA,
  no system/user/debug override. Raw SSLSocket separately uses app-only
  KeyStore+HTTPS endpoint identification, not an assumption XML covers raw IO.
- https://android.googlesource.com/platform/packages/modules/adb/+/HEAD/docs/user/adb.1.md
  ADB server host/port/socket selection, fixed serial, reverse list/no-rebind/
  remove semantics. ADB source is an external broker to include in boundary,
  not evidence that the broker is safe outside the no-uplink namespace.
- https://developer.android.com/studio/run/emulator-commandline
  Documented fixed console/ADB ports, no-snapshot, private data/system images,
  noaudio, camera none, no-window, software GPU and explicit KVM acceleration.
  No guessed gRPC-disable switch selected yet: actual pinned binary's listening
  sockets/options must be validated before readiness. Private namespace remains
  primary no-uplink boundary, no claim emulator flags alone contain all traffic.
- https://developer.android.com/tools/aapt2
  Offline resource compile/link/generated Java workflow underlying held build.
- https://developer.android.com/tools/apksigner
  Alignment precedes signing, signature verification/certificate output needed.

Current build/ADB sources remain FALSE-gated. Runtime closure, complete emulator
wrapper/control handoff and attribution/negative-control drivers are unfinished.
Typed product profile/schema/adapter/readback are prepared, default host disabled. Documentation is not an authorization or an execution result.

- https://api.adoptium.net/v3/assets/feature_releases/17/ga?architecture=x64&heap_size=normal&image_type=jdk&jvm_impl=hotspot&os=linux&page=0&page_size=1&project=jdk&sort_method=DATE&sort_order=DESC&vendor=eclipse
  Official Temurin17 Linux x64 JDK metadata selected jdk-17.0.21.1+2. Archive
  retrieved as bytes and verified against official size/SHA256, recorded with
  exact returned archive URL. No extraction or JDK execution. Host libc/loader
  and complete transitive runtime closure remain unresolved.

- https://android.googlesource.com/platform/packages/modules/adb/+/HEAD/adb_listeners.cpp
  The current format_listeners implementation emits (reverse) in the first
  column for reverse mappings, not the emulator serial. Held validator matches
  that literal and the fixed port pair. Exact pinned platform-tools behavior
  still needs verification before readiness, rather than assuming HEAD is binary proof.

- https://android.googlesource.com/platform/system/core/+/android-10.0.0_r1/adb/adb_listeners.cpp
  Android10 reference source has the same reverse-column formatting. This is
  relevant to the candidate API29 guest adbd, still not proof of the r8 image.
