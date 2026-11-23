# Test fixtures

`AnalysisTest.dex` is copied from the [androguard](https://github.com/androguard/androguard)
test corpus (`tests/data/APK/AnalysisTest.dex`), which is licensed Apache-2.0.

It is 1 KB, contains a single class `LAnalysisTest;` with four methods, and exists so that the
dex adapter's tests run in CI without downloading anything. It is a *fixture*, not an analysis
artefact: the repository convention banning `*.apk` / `*.dex` exists to keep uploaded
applications and decompiled output out of git, and `.gitignore` makes an exception for this
directory only.

What it does **not** prove: that MOBIUS handles real, obfuscated, multi-dex applications. Those
have been exercised manually (see `docs/REVIEW_LOG.md` RL-006) but are not reproducible here.

`build_provider_flow_dex.py` adapts the in-repository `build_flow_dex.py` DEX
assembler to generate deterministic provider-query bytecode in memory. No
compiled third-party APK or new binary is checked in. The query method has the
Android provider descriptor and passes its selection argument to rawQuery; the
constant-query variant is a bytecode negative control. SHA-1/Adler32 header
checks, Androguard instruction/register decoding and the actual detector/service
path are tested. Independent decompiler/Android verifier review has NOT been
performed for this new fixture.

This is a STATIC fixture, not an installable Android application. It has no
constructor/usable database receiver and no runtime provider routing/row oracle.
It MUST NOT be registered as an executable lab contract or used as evidence of
runtime readability, attacker access or ordinary-application UID exposure.
