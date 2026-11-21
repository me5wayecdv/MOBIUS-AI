# Held native positive capture/request-replay slice

PREPARATION ONLY. All execution entry points have source-code false gates. None
of these modules has been imported, installed or launched during preparation.
AST parsing and wheel hash/download checks are the only validation performed.
This is a local owned fixture, not the held full harness or product integration.

## Concrete components

- `installer.py`: future ephemeral CI root staging only. Requires CPython3.12,
  x86_64, glibc>=2.28; verifies all regular wheel files against hashes, creates
  `/opt/d061-runtime/venv` without pip, uses separately hashed pip24.0 wheel to
  install the explicit42 package lock with no index/source builds/dependency
  fetching. Runs pip check. Does not install into product/baseline environment.
- `wrapper.py`: future ephemeral CI root supervisor only, not a workstation
  command. Anonymous network/mount/PID namespaces wrap driver, proxy, client and
  origin from launch. Read-only chroot exposes runtime/library binaries, fixture
  sources, public CA certs and dedicated random/null devices, not host homes,
  /run,/var,/tmp,/sys, host service sockets or a shared /dev tree. Fresh tmpfs/tmp,
  private evidence/work. Only loopback interface is brought up and checked.
  New proc mount reflects the PID namespace. setpriv drops all bounding,
  inherited/ambient capabilities, UID/GID65534 and groups, sets no-new-privs;
  resource limits and FD closure precede fixture execution. Clean environments,
  absolute executable paths and DEVNULL stdin are explicit. Source/runtime
  staging must be from reviewed checkout/root-owned inputs on a clean runner.
- `driver.py`: additionally checks nonroot/no effective or bounding capabilities
  and no-new-privs. Creates trusted fixed policy/nonce/profile. /proc listener
  ownership and CA readiness replace TCP probes, so readiness generates no
  abort/empty connection events. Uses one verified-TLS GET via regular proxy
  CONNECT, no client retries. Waits boundedly for native request replay.
- `addon.py`: pinned native FlowWriter -> bounded native FlowReader, rejects HAR,
  requires one loaded HTTPFlow, revalidates its fixed policy and exact stored
  request state, calls pinned ClientPlayback.check before enqueue. Explicit
  enqueue/start/completion/error/terminal evidence. Captured native flow enters
  replay.client once; no hardcoded request reconstruction or response playback.
- `origin.py`: separate stdlib HTTPS server writes independent receipt IDs and
  sequences. `wire.py` shares exact canonical method/path/safe headers/empty body
  policy across initial native flow, replay native flow and both origin receipts.
  Raw header pairs are retained. Duplicate headers, credentials, framing headers,
  wrong Host authority, trailers, WebSocket, other endpoints/methods/body fail.

Only regular mode is enabled. No browser/transparent/local/WireGuard capture or
DNS proxy/helper mode is requested. Presence of helper distributions/default
addons is not a claim they execute or send telemetry; their reviewed startup
behavior remains a technical review item.

## Quiescence and failure semantics

All producers stop before final exact2 receipt/event counts are read. Every
native/backend canonical request must match; raw evidence remains. Backend
receipt IDs are unique and sequences1/2, not wallclock-only. Exactly one
native enqueue/start/completion and a successful addon terminal record are
required. Positive flow/backend/addon errors and error/exception/traceback log
markers fail the candidate. There are no negative cases mixed into this first
positive case. TLS-negative controls remain explicitly UNTESTED.

Driver cleanup is signal-aware, bounded TERM/INT then KILL/wait and atomic
cleanup evidence. Wrapper has its own ordinary-signal/deadline cleanup, kills
namespace supervisor/process group and reaps it. PID1 exit kills its namespace
members including new process groups/nested PID namespaces; the anonymous netns
has no persistent name. Wrapper removes signing material even if driver died
before finally. These are unexecuted source intentions, not observed cleanup or
OS-boundary proof. Review signal/timeout paths before any activation. Host kill
of the entire CI job remains the platform's final emergency boundary.

No candidate result is a whole-project pass. First real slice, if separately
reviewed/activated, can establish only positive local capture/request replay
with positive verified TLS, not TLS rejection controls, Android/Allsafe,
streaming, HTTP/2, redirects or broad containment/general app coverage.

## Hash-closed toolchain preparation

- `requirements.lock`: all42 resolved runtime packages pinned, one selected wheel
  SHA256 each. CPython3.12, Linux x86_64, glibc>=2.28 only. No extras.
- `wheel-lock.json`: exact filenames, observed PyPI URLs, matched wheel SHA256
  and declared requirements. Downloaded binary-only under existing pip24.0 on
  existing CPython3.12.16, no installs. A second no-index wheel-only
  pip download --require-hashes against the local wheelhouse succeeded for42.
- `bootstrap-lock.json`: separate pip24.0 wheel SHA/URL verified, ZIP only. It is
  installer tooling, not a new product dependency. Total downloaded wheels43.
- mitmproxy12.3.1 SHA256:
  `87afb808ac8d55383dbe6aa30eadeb0fedaeffd26210e7e23c25c9cd43bdb36a`.

The installer records actual interpreter, base prefix, glibc/OpenSSL/kernel/OS
and provider-reported ImageOS/ImageVersion. A hosted runner image digest is not
invented where unavailable. Current artifact is platform/hash pinned, not a
claim of an immutable hosted OS image. Future run must record actual supported
runner version and reject a toolchain mismatch. Runtime wheel download is absent.

## Remaining exact review gate

Review this combined installer/wrapper/driver/addon/wire/origin revision plus
all43 wheel identities. In particular check the chroot interpreter/library and
OpenSSL config paths, regular default addons/native helpers, setpriv/unshare
supported flags, namespace death/wait evidence, signal/deadline/key cleanup,
resource limits, source staging and inode listener ownership. No runtime has
validated any of those paths. Do not merge permission with execution approval:
source gates stay FALSE until exact technical review and a separately bounded
activation patch. No spending, account, production, secret-disclosure or real
third-party target authority is added.
