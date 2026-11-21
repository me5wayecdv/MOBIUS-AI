# Safe PoC / TestPlan contract (D-040)

A PoC plan is a typed description of a bounded proof against an authorized lab APK,
emulator, or local harness. It is not a shell script. Model output cannot provide commands,
URLs, arbitrary executable paths, or unrestricted arguments.

## Scope binding

Every plan carries the investigation ID, authorization ID, exact target SHA-256, target
package, and one or more hypothesis IDs. The execution service must re-check these values
against persisted investigation and authorization rows immediately before running.

## Closed action registry

Allowed step actions:
- `assert_manifest_component`
- `assert_manifest_permission`
- `invoke_local_harness`
- `assert_local_harness_result`
- `assert_emulator_package_present` (emulator targets only; boolean `expected_value`;
  target must equal the plan's authorized package)
- `assert_emulator_provider_rows` (emulator targets only; non-negative integer
  `expected_value`; pass when at least that many rows are readable without a permission;
  target must be one authority path inside the authorized package)
- `assert_emulator_frida_classes` (emulator targets only; non-negative integer
  `expected_value`; observation-only Frida attach counting loaded classes; requires the
  `non_destructive` safety class, so it flows through the approval gate with cleanup;
  target must equal the plan's authorized package)

Cleanup actions:
- `remove_temporary_workspace`
- `reset_local_harness`
- `stop_emulator_instrumentation` (emulator targets only; stops frida-server, idempotent)

Each step has a bounded target reference and timeout. No free-form command field exists.

## Safety and budgets

- Maximum 20 steps and 300 seconds total.
- Per-step timeout is 1–60 seconds.
- Output is capped at 1 MiB.
- State-changing plans require explicit approval.
- Non-read-only plans require cleanup steps.
- Manifest assertions cannot target a local harness.
- Emulator adb probes cannot target a non-emulator target kind, and stay read-only.
- Frida instrumentation probes are non_destructive (approval + cleanup), observation-only.

D-040 defines the contract only. D-041 implements allowlisted adapters; D-042 persists
reproducible execution evidence; D-043 owns approval, timeout, cancellation and cleanup.
No plan is executed by schema validation.
