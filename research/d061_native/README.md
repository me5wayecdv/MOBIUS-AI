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

## Combined cleanup and activation review revision

`activation-workflow.yml.proposed` remains outside active workflows. It targets
ubuntu-24.04 and CPython3.12 with actual runner/interpreter version recording,
SHA-pinned checkout/setup-python/upload-artifact actions, no saved checkout
credentials, manual exact reviewed-SHA comparison and non-cancelling concurrency.
`activate.py` independently holds INSTALL_ONLY and POSITIVE_FIXTURE at FALSE.
A later exact activation disposition can allow install-only while leaving the
positive runtime false. The orchestrator stages root-owned source copies and
records original file digests; only the selected reviewed mode's source gate is
changed in that copy. Product checkout and three original source gates stay
false. No submitted workflow, import, installation or execution is implied.

`stage_wheels.py` performs only allowlisted HTTPS wheel downloads and SHA checks.
`installer.py` is the isolated no-index43-wheel path above. Positive mode, if
separately authorized, calls the exact namespace wrapper. No apt, elevated proxy,
transparent/native-helper workaround, model/Android/Allsafe/product action is in
this proposal. Workflow collects sanitized diagnostics with always() even when
command fails, and then uploads only the safe collector output directory.

`cleanup.py` masks ordinary INT/TERM/HUP signals during bounded cleanup. Driver
and wrapper independently guard each signal, wait, fallback kill/reap, key/home
removal, root removal and evidence write. Original error and all observed cleanup
errors are retained. Original failure is not replaced with a clean result;
incomplete cleanup invalidates candidate-result and exits nonzero. Wrapper also
scans host-visible process netns references after supervisor exit. SIGKILL,
whole-host loss or filesystem failure can prevent any software's final evidence;
those limits remain, not a claim of guaranteed cleanup under host loss.

Before any positive fixture process launches, namespace setup records actual
links/addresses, IPv4 and IPv6 all-table routes/rules, iptables/ip6tables/nft
rulesets, namespace IDs, effective launch, privilege status, limits, clean env and
actual tool versions. Any requested namespace command failing blocks the launch.
Host before/after snapshots are retained too. No traffic/capture readiness probe
is substituted for this evidence. These paths remain runtime-untested.

`collect.py` has a literal bounded file allowlist, rejects symlink components and
nonregular files, records hashes/missing files/copy errors, never recurses into
raw output and never uploads private HOME, origin.key or CA key files. Candidate
result is copied only after zero command exit and complete wrapper cleanup;
required evidence is checked by mode. Failure artifacts include original/error,
cleanup, source activation, command and safe logs even on nonzero exit. Artifact
collection itself cannot turn a failed command into success.

The combined patch has AST-only Python and YAML syntax parsing. No new tests
simulate runtime success or manufacture network evidence.

## Outer lifecycle and copy-completeness correction

`activate.py` now uses owned Popen plus signal-aware bounded teardown instead of
subprocess.run(timeout) killing only a wrapper. Linux prctl parent-death coupling
is armed and parent identity rechecked before exec: an abruptly dead activation
parent sends TERM to its command, and a dead wrapper sends KILL to its exact
unshare supervisor, whose --kill-child kills namespace PID1. The installer's
subcommands also arm parent-death KILL. Coupling is never a generic host kill.
Normal cancellation attempts30 seconds graceful teardown then bounded KILL/reap.
Wrapper420-second outer budget accounts for snapshot140+namespace75+teardown8+
post-snapshot140+overhead; reaching it still triggers owned teardown rather than
assuming inner cleanup already ended. Workflow18-minute ceiling leaves room for
both stages, staging and sanitized upload. SIGKILL/host loss remain limits.

Independent always-run `emergency.py` validates recorded PID+starttime+boot-ID
identities, uses pidfd with recheck before killing exact still-owned identities,
waits for death and removes only exact recorded jail/private-key/home paths.
Record-before-wait plus parent-death coupling covers the Popen-to-record gap.
It never adopts a namespace/process by prefix. The recorded jail directory name
is constrained under /opt only for deletion, not used to discover other work.
Every command stage now records argv, rc-or-null, original timeout/exception and
all teardown errors on every exit path. Partial command diagnostics are retained.

Collector checks lexical/lstat path components before resolving or reading,
then opens leaf files O_NOFOLLOW. Known mode is required. Positive success needs
all named native bytes+digest, both receipt/event sets, replay enqueue/start/end,
addon terminal, driver/wrapper cleanup and candidate result actually copied,
not merely present upstream. Missing/rejected/failed copies invalidate success
and remove a copied candidate. Failure-safe bounded allowlist remains unchanged
in audience/scope. Only source/AST/YAML checks, no live namespace signals or
runtime tests were executed for this correction.
