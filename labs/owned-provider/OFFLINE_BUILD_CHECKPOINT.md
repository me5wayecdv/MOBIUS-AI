# Offline unsigned build checkpoint, 2026-11-23

Actual local compilation succeeded with the committed build script, API28 platform revision6, Android build-tools35.0.0 and Eclipse Temurin JDK17.0.21.1+2. No Android app execution, signing, installation, emulator or external target was used.

Unsigned APK SHA256: `a6de8448c2ce6658a7af45c83c7063b6d443cc9e909bcf1086656ed8dc6fec20`.

Toolchain sources and integrity checks:

- Google repository metadata: https://dl.google.com/android/repository/repository2-1.xml
- API28 platform: https://dl.google.com/android/repository/platform-28_r06.zip , SHA1 matched metadata `9a4e52b1d55bd2e24216b150aafae2503d3efba6`.
- Build tools: https://dl.google.com/android/repository/build-tools_r35_linux.zip , SHA1 matched metadata `2cfaa0bbb2336e9ec18ed3ecea84fa2e2af607bc`.
- JDK release: https://github.com/adoptium/temurin17-binaries/releases/tag/jdk-17.0.21.1%2B2 . Archive SHA256 matched its published checksum `0b0ac5eab6db6abaec68c9913bcddb31321e5da411c45073d520d9c125e6f7b4`.
- aapt2 reports2.19-11948202; D8 reports8.6.2-dev, build abaab469b5ebd4dd2bb91ba0ed6f45277faae4ca.

Observed checks:

- javac/aapt2/D8 compile exit0.
- Android aapt2 dump of the compiled manifest shows package, exact authorities, positive exported=true, private exported=false, no grants, backup/debuggable=false.
- Android dexdump disassembly exits0 and shows real constructors, onCreate database initialization/seed and the query implementation. This is an independent Android-tool parse/disassembly, NOT ART verification or runtime execution.
- The Mobius parser reads nine app methods and produces one static read may-flow for NotesProvider. It does not find a flow for the inherited private implementation, so that analysis is not a whole-program coverage claim.
- apksigner verify deliberately fails with missing META-INF/MANIFEST.MF. The artifact is genuinely UNSIGNED and cannot be installed as delivered. No signing key has been made or requested.

No exact-APK runtime contract is registered, and the unsigned digest must not become one. Remaining: independent review of source and artifact; scoped signing and signature verification; approved disposable-emulator execution to establish initialization, positive plain read and actual private denial; then approval-bound connected hypothesis/runtime/report. The read query has no selection, so it does not validate an injection claim about selection may-flow. No full-agent success is claimed.

## Local disposable signing checkpoint

A separate local copy was aligned and signed once successfully with a new disposable RSA2048 lab-only identity. No existing account or production key was touched. Newly generated temporary keystore/password files were removed after verification. The identity cannot be regenerated from the retained public certificate, and must not be silently replaced.

Signed APK SHA256: `6b7081010eb6dfb2b90e27b94a761020528e4ea8b17d300bdd372e0b130deca8`.

Certificate SHA256: `197ce8054d16f0c8bded9802c0ada2a4908ed0f7fd1b923decb7d37c1074f75c`.

Android apksigner verification exits0 with v2=true, v3=true, v1=false and one signer. All original ZIP entry content, including compiled manifest/resources/DEX, compares byte-identical to the reviewed unsigned APK. Signing added META-INF records and an APK signing block. This is content comparison, not a reproducible-build proof. Two earlier local signing attempts failed on password-file reuse; their temporary material was also removed. No private signing material was logged or committed.

The signed artifact is retained locally only. No upload, installation, ART execution, emulator, model journey or runtime contract is authorized by this checkpoint. Do not substitute the unsigned digest or a rebuilt/re-signed artifact for the exact signed digest above. The read-only evidence conclusion and all runtime limits remain unchanged.
