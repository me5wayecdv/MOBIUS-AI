# D061 first native local positive result

Run https://github.com/me5wayecdv/MOBIUS-AI/actions/runs/44883271361
completed SUCCESS at main `9f8ede5c6e08efae4c94d76becdaec2de9181558`.
Exactly one actual experiment was dispatched. The earlier branch-only workflow
registration404 started no experiment. No retries followed the real run.

## Provenance and offline verification

- Artifact14697799735, `d061-native-positive_fixture-44883271361`,29679 bytes.
- Archive SHA256
  `aee162f147566978068cd0e61417e8614e08fb2ba92b687f5d33b85e483c2152`.
- All31 copied file hashes independently matched collector manifest. All43
  staged filenames/digests matched reviewed42-package runtime lock plus hashed
  pip24 bootstrap. Source activation record and command/cleanup records retained.
- Installer installed42 packages into isolated venv; pip check found no broken
  requirements. Runtime Ubuntu24.04.5, image20261116.376.1, CPython3.12.16,
  glibc2.39, OpenSSL3.0.13, util-linux2.39.3. No immutable image digest claimed.

## What actually happened

- Real3201-byte native HTTPFlow captured, SHA256
  `81cf28d6e69e35c109d81edd5d0e7a970f6e263cdadfeebf93a41dcbda50206d`.
- Actual empty-body HTTPS GET to fixed loopback origin, status200. Pinned native
  FlowReader loaded the captured bytes and ClientPlayback replayed that request.
  Exactly one enqueue/start/completion, same native flow ID, initial replay
  marker null then request replay marker. Addon terminal state completed/noerror.
- Independent backend ledger has exactly two distinct receipt IDs, sequence1/2,
  both TLSv1.3. Initialnative/replaynative/bothbackend canonical fingerprints
  agree, raw ordered headers retained. Proxy log independently shows initial
  GET200 and native replay GET200, not response playback.
- Independent review also decoded original native bytes offline with a stdlib
  tnetstring parser, rather than trusting only proxy JSON projection. It
  confirmed one complete native HTTPFlow with the stated request/response/TLS.

## Boundary and cleanup evidence

- Separate actual network/mount/PID namespace IDs, onlylo127.0.0.1 and::1,
  local-only IPv4/IPv6 alltable routes, ordinary rules, empty namespace firewall
  output, all14 snapshot commandsrc0. Host namespaces unchanged. Host before/
  after14command stdout/rc pairs match under numeric firewall-counter/generated
  timestamp normalization only.
- Namespace status snapshot is ROOT SUPERVISOR BEFORE privilege drop. Do not
  label it a nonroot child snapshot. Source driver guard passed before launching
  processes: nonroot, no effective/bounding capabilities, no-new-privs. Actual
  per-child privilege/FD readbacks were not separately retained.
- Normal cleanup: proxy0, originTERM-15, no driver errors, private keys absent.
  Wrapperexit0, complete/noerrors, supervisor exited, remaining namespace members
  empty, jail absent, keys absent. Emergency check found recorded identities
  already absent or changed, not a live emergency-kill exercise. Collector
  copied full positive evidence, no copy errors or private signing material.
- Timeout/repeated-cancellation/PDEATHSIG/emergency-kill paths remain reviewed
  source intentions, not exercised failure-path evidence. SIGKILL/host loss can
  prevent final cleanup/evidence. This is a bounded trusted local fixture, not
  a universal hostile-code sandbox or all-traffic/zero-egress proof.

## What this does not establish

This is real native local capture/request replay with positive verified TLS,
not Android/Allsafe traffic, product authorization/run/evidence/report wiring,
TLS rejection controls, streaming, HTTP/2, redirects, certificate pinning, full
D061 or whole-project completion. TLS-negative controls remain UNTESTED.

Next smallest slice is explicit product wiring of this same fixed fixture,
with case/plan/target provenance and immutable evidence/readback, plus separately
specified local TLS rejection cases. It must not relabel local traffic as APK
execution or bypass existing authorization/approval gates. No new standalone
fixture milestone replaces that unfinished product outcome.
