# Path from held source to owned-APK evidence (planning only, nothing here is approval)

Every row names the gate, what source already exists, and who must decide. No row is executed by this document.

| # | Remaining gap | Source state | What unblocks it | Decider |
|---|---|---|---|---|
| 1 | Reviewed source lock and stage lock (per-member sha256, mode, destination, transitive SDK/JDK/Python/ELF/launcher closure) | Validators, watchdog final validation and `stage_archives` consume the lock. No lock exists. | Member hashes need reading archive members. Reading and hashing members, even in memory, is SDK extraction under the current hold. Central-directory listings alone give names and sizes, not sha256. | User/main: explicit approval of in-memory hash-only member reading, plus the SDK license-review flag |
| 2 | Root runner with PID namespace, cgroup caps, outer-owner recovery handle | Watchdog uses a PID namespace (unprivileged-tested only). Independent recovery is strictly UNVERIFIED. | A disposable root host or runner that can create a cgroup and a persistent containment owner. Not available in the CI free tier as reviewed. | User/main: whether a root-capable free runner is acceptable, then a reviewed run |
| 3 | Real fault, cancel and SIGKILL evidence | Benign-child tests only. | A run under gap 2, with fault injection against the real stager. | Follows gap 2 |
| 4 | Device runner for TLS negatives | `app_negative_preparation` (build), `negative_verdict` (held predicate). No runner. | Emulator, ADB, KVM and APK build are all held. Needs gaps 1 and 2 first, plus clock mapping and certificate originals. | Follows gaps 1 and 2 |
| 5 | Workflow wiring (staging, export, packer, upload) | Gate list in the workflow yml source covers the watchdog. Nothing registered or dispatched. | Android workflow registration and dispatch are held. | User/main |
| 6 | Positive owned-APK product evidence | Exporter, manifest binding and packer are held source. | Gaps 1 to 5 complete, then one authorized run. | User/main |

Free-only, no new accounts or keys, no merge, no activation at every step. A green CI run or a source checkpoint is not approval for any row.
