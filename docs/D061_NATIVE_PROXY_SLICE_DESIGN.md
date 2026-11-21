# D-061 minimal native proxy slice: pinned inventory and design, held

Research only, no installation/import/launch of mitmproxy or target. No emulator
or Android toolchain needed for the first proposed standalone slice. It would
prove only standalone proxy machinery, not Android or Allsafe support. Runtime
still needs exact review and dependency disposition.

## Pin and inspected source

Candidate: mitmproxy 12.3.1, Python >=3.12.
Metadata source: https://pypi.org/pypi/mitmproxy/json
Exact wheel inspected as ZIP, not installed or imported:
https://files.pythonhosted.org/packages/a7/b2/886992a28a7bf86e47691d7a33e26eba370ee71d89b77d3128412910a33e/mitmproxy-12.3.1-py3-none-any.whl

The same exact observed address is in the dependency manifest JSON. SHA256
verified before source inspection:
87afb808ac8d55383dbe6aa30eadeb0fedaeffd26210e7e23c25c9cd43bdb36a.

Inspected wheel paths: mitmproxy/io/io.py, addons/clientplayback.py and http.py.
FlowReader.stream yields native Flow objects, migrating saved states; it also
accepts HAR. For this slice explicitly reject HAR and require captured native
HTTP flows with provenance. clientplayback.start_replay checks flows, marks
is_replay=request, clears response/error and queues a request. Its
replay.client.file command loads flows then invokes start_replay. This supplies
a concrete request-replay route distinct from returning a saved response.
No invocation or compatibility claim has been tested.

## Existing vs new and installation boundary

Existing project uses Python, stdlib ssl/http/json/hashlib/subprocess, Mobius
FastAPI/sqlalchemy/sqlite stack and pytest. Local environment has Python3.12,
openssl and ip; these observations do not prove the next CI runner inventory.
No mitmdump, adb, gradle or tcpdump executable was found locally. The existing
Mobius virtualenv has no pip module. Do not infer an absent package from that.

NEW dependency proposal: mitmproxy plus its complete resolved transitive wheel
set in an isolated CI-only virtualenv. Never add it to product dependencies
without separate disposition. Metadata includes mitmproxy-rs, aioquic,
cryptography, pyOpenSSL and other packages, so this is not a pure-stdlib install.
Exact declared requirements are preserved in D061_PROXY_DEPENDENCY_INVENTORY.json.
They are constraints/ranges, NOT a resolved lock. No transitive pin is invented.

Before any installation: approval/disposition of new tooling, resolve for one
pinned Python/platform, record every wheel/version/URL/SHA256, reject source
builds, install from that reviewed wheelhouse with no-index/require-hashes, then
record installed versions. Network dependency staging must finish before the
no-uplink runtime; no automatic runtime downloads. An after-the-fact freeze is
not a lock. OpenSSL CLI could generate fixture certificates only after its
existing-runner availability/version is checked; avoid another dependency if
stdlib plus reviewed existing OpenSSL suffices.

Android later adds a distinct held fixture build boundary (Gradle/AGP/build-tools,
platform/system image/emulator plus helpers and hashes). It is deliberately not
part of this minimal standalone slice and not approved by proxy-tool disposition.

## Minimal standalone native flow/extractor/replay design

1. Reviewed no-uplink namespace, fresh unprivileged runtime, FD/broker hygiene
   and loopback-only mock HTTPS origin, proxy and stdlib client. No external
   endpoint/DNS resolution or network canary. Independent endpoint map provided
   by trusted harness config, not evidence's own scope label.
2. One fresh nonce, one empty-body GET, no cookies/Authorization or redirects,
   exact allowlisted scheme/hostname/port/path. GET alone is not safety; the
   fixed origin only returns a test receipt and cannot perform writes.
3. Save real native flow, stop/flush capture, hash bytes. Bounded extractor uses
   the pinned FlowReader and requires exactly the intended HTTP flow. Extract
   original method/scheme/authority/host/port/path, ordered header fields, raw
   body hash/length, response status, flow ID/timestamps, connection/TLS metadata,
   capture hash and extractor version. Keep original native bytes. Parser limits
   on file size/flow count/body/header lengths precede processing.
4. Replay that captured HTTPFlow through native client replay, never reconstruct
   a request from a hardcoded URL. Gate method/endpoint/headers/body again before
   enqueue. No redirect following. Keep upstream certificate verification on.
   Independent mock-origin ledger must show exactly initial plus one additional
   receipt with distinct receipt IDs and identical normalized request fingerprint
   and nonce. A replay-marked flow alone is insufficient.
5. Separate TLS controls: valid test trust with normal hostname check, rejected
   untrusted CA, trusted chain with wrong hostname rejected for hostname reason,
   verified valid upstream and rejected invalid upstream. Keep original errors
   private, persist fixed classified outcomes plus source hashes. No system CA
   modification, arbitrary app pinning bypass or application-auth claim.
6. Product integration is a later exact action/allowlist change: read back live
   investigation, target authorization and immutable approved plan, expiry,
   revocation and intensity before execution. Persist native flow/receipt/TLS
   artifacts via evidence service, link actual run and report, and read back
   artifact digests. Synthetic CI approval is not owner approval. No adapter
   currently exists for this standalone slice, so it cannot be called a product
   end-to-end journey until that wiring actually runs.
7. Bounded cancellation/cleanup and final topology/process evidence, preserving
   failed evidence and distinguishing normal-path results from SIGKILL limits.

Next useful work is exact dependency disposition plus reviewable real native
extractor/replay implementation against that pin, not more synthetic positive
fixtures or repeated infrastructure preflights. Runtime and installs stay held.
