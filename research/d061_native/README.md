# D061 native proxy slice: concrete held preparation

Status: PREPARATION ONLY. No dependency installation/import, proxy execution,
origin launch or target launch has occurred for this proposal. The driver has a
source-code false gate, no environment bypass. This is a separate local fixture,
not the held full harness or an Allsafe demonstration.

## Toolchain and resolved lock

- Target: CPython 3.12, Linux x86_64 with glibc >=2.28. No ARM, macOS,
  Windows or musl claim. Exact future runner image/OS digest still needs pinning.
- Existing pip24.0 under existing Python3.12.16 resolved and downloaded 42 wheels,
  with binary-only resolution, no source builds and no package installation.
- `requirements.lock` pins every resolved dependency with one selected wheel
  SHA256. `wheel-lock.json` includes the filenames, exact observed PyPI URLs,
  declared requirements and independent PyPI digest matches. No extras enabled.
- A second no-index wheel-only `pip download --require-hashes` against the local
  wheelhouse succeeded for all 42 pins. This verifies dependency/hash closure
  under that resolver/interpreter, not importability or runtime safety.
- mitmproxy12.3.1 wheel hash:
  `87afb808ac8d55383dbe6aa30eadeb0fedaeffd26210e7e23c25c9cd43bdb36a`.
- No modifications to product dependencies, no container/image publication,
  no install into product or current baseline environment. Future installation,
  if reviewed, must be a throwaway venv using this exact lock and wheels, with
  `--no-index --require-hashes --only-binary=:all:`. Toolchain review must inspect
  the full 42-wheel inventory and decide whether automatic default addons and
  Linux native helper dependency are acceptable for this isolated fixture.

## Exact proposed path

1. `driver.py` takes a new private output directory and isolated venv path. It
   writes a trusted fixed profile, nonce and local-only endpoint policy. Captured
   flow metadata cannot choose profile, scope, target or endpoint.
2. Runtime-only OpenSSL generates an ephemeral SAN127.0.0.1 TLS certificate.
   `origin.py` binds loopback18443; only nonce-bearing GET with empty body passes.
   The backend writes its own receipts before responding. It is independent of
   the proxy projection, but shares this explicitly local fixture's policy.
3. mitmdump binds loopback18080, lazy connection, verified upstream certificate,
   HTTP/2 off and serial native replay. Addon CONNECT/request policy denies other
   endpoints/methods/path/headers/body. These checks are fixture guards, NOT an
   OS network boundary or universal containment. No third-party target is used.
4. The Python stdlib HTTPS client makes one TLS request through CONNECT and
   verifies the generated proxy CA. It does not ignore TLS verification. A
   failed client request stays failed, no application/client retry loop.
5. `addon.py` writes the actual completed HTTPFlow with FlowWriter, flush/fsync,
   hashes its native bytes, bounds file size, rejects HAR and loads it with
   pinned FlowReader. It requires one HTTPFlow and exact request-state equality.
   Pinned native `replay.client` receives that loaded flow once, not a hardcoded
   reconstruction, HAR replay, response playback or an invented response.
6. A second independently recorded backend receipt plus native request-replay
   completion is required. Exactly two receipts/events, equal native request
   fingerprints and TLS flags are checked. No model is called. Cleanup sends
   TERM then bounded KILL/wait, removes private CA/signing keys from artifacts.

## Review gaps before activation

- Review source and fixed options against the selected wheel. Syntax/AST-only
  checks passed; none of these modules has been imported. Local runtime unknown.
- Pin runner image and verify glibc/CPython/OpenSSL, owner UID, resource limits,
  loopback-only sandbox boundary and inherited descriptors before activating.
- Readiness currently waits for proxy CA file, not both listening sockets. Add
  bounded readiness without making successful application probes or retries.
- Tighten independent backend-to-flow comparison: nonce/TLS/count and proxy
  fingerprint equality are present, but compare each backend receipt's complete
  canonical method/path/headers/empty-body fingerprint to the corresponding
  native event too. It must fail on lost/reordered/mismatched receipts.
- Add explicit process exit/cleanup evidence and fail the result if cleanup is
  incomplete. Current finally cleanup is operational, not evidentiary proof.
- Exercise negative cases with real captured bytes only after review. No more
  synthetic evidence layers are needed. No target authentication, Android,
  product integration, request streaming, HTTP/2, redirects or capability-wide
  native/TLS claim follows from this bounded GET fixture.


Installation and execution remain operationally held pending exact toolchain and
harness review. Preparation adds no spending, account, production, disclosure
or third-party target authority.
