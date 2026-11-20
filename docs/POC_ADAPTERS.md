# Safe PoC adapters (D-041)

D-041 currently provides two execution surfaces:

1. **Persisted manifest assertions** for a `lab_apk` plan. These read only same-investigation
   `fact` observations and do not execute APK code.
2. **Two deterministic local harnesses** for a `local_harness` plan:
   - `unsafe_webview_forwarder_v1`: models an exported input being forwarded to a WebView sink.
   - `safe_webview_guard_v1`: negative control that blocks non-HTTPS / non-trusted-host input.

3. **Read-only emulator probes** for an `emulator` plan (PHANTOM first slice,
   `services/phantom.py`). Two probes run through `adb` with fixed argument
   lists: package presence (`pm list packages`) and content-provider row
   counting (`content query`). The adapter is only constructed when
   `MOBIUS_PHANTOM_ADB` (and optionally `MOBIUS_PHANTOM_SERIAL`) is set, and it
   verifies `ro.kernel.qemu` on the device before every probe, refusing
   physical devices. Without the environment a plan on an emulator target
   still fails closed with `PoCAdapterUnavailable`. No install, delete, write,
   Frida, or proxy capability exists in this slice.

The local harness is an explicitly labelled simulation, not execution of the APK. It makes no
network requests and performs no process execution. No arbitrary shell, command, URL fetch,
or state-changing adapter is registered.

Before any step, the runner revalidates the investigation, authorization, APK SHA-256, package,
authorization expiry/revocation/intensity, and same-investigation hypothesis IDs.

D-041 returns an in-memory execution result. D-042 persists reproducible evidence; D-043 adds
approval, cancellation, timeout and cleanup orchestration.
