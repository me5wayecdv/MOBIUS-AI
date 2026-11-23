# Owned provider lab, preparation only

This source is not an APK, installation proof, independent review, runtime contract or user authorization. Nothing registers it in the application. An offline unsigned Android build has now succeeded; device execution has not been performed. See OFFLINE_BUILD_CHECKPOINT.md.

The intended fixed package is `com.mobius.ownedlab`. The exported `NotesProvider` exposes `content://com.mobius.ownedlab.notes/note`. A separate manifest-non-exported `PrivateProvider` uses `content://com.mobius.ownedlab.private/note` as the denial control. Both create only one fixed synthetic row in a private in-memory database. No Internet permission, persistent database, activity, receiver, service, write operation, or URI grants are requested. Caller selection reaches SQLite query for static may-flow analysis. This is not an SQL injection proof. PrivateProvider inherits query, but Android must enforce non-exported access before entering it.

`build-unsigned.sh` consumes an already-installed API28 android.jar and build tools through explicit environment paths. It does not download, sign, install, execute on Android or publish anything. Its output is explicitly unsigned. The deliberately old target28 is for this contained fixture only, never a distribution recommendation. Do not install it on personal/production devices. Byte-for-byte repeatability is not claimed across tool versions.

Remaining gates, in order:

1. Independent review of source, exact SDK/build-tools/JDK versions and applicable SDK terms.
2. Offline compile using real Android tools, retaining tool versions and source hashes. None of the hand-assembled static DEX fixtures substitute for this build.
3. Independently inspect produced manifest and DEX with Android tools, compare to source, verify signature after a separately approved signing route and record exact signed APK SHA256. Signing secrets must never enter source or chat.
4. Verify both provider initialization and constructor behavior on an explicitly approved disposable emulator. Require shell UID2000, installed base APK hash, exact serial, positive row read and independent private-provider permission denial. This proves shell exposure only, not ordinary app UID exposure or a security vulnerability.
5. Independent source/artifact review supplies a real review digest. Only then can an explicitly scoped host register an exact-APK ProviderReadContract with the real serial. No dummy digest, default registration or model-supplied route is allowed.
6. Connect genuine parsed flow evidence through a cited hypothesis, reviewed approval-bound plan, bounded runtime evidence and conservative verdict/report. Model approval and device/runtime approval remain separate. A deterministic or mocked hypothesis cannot be labelled a real model result.

The source is intentionally minimal. Java compilation succeeded with the recorded toolchain. Android runtime semantics remain unverified until those gates are actually run. A passing source-shape test is only a regression check, not an independent verifier.
