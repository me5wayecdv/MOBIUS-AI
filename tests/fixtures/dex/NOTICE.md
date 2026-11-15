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
