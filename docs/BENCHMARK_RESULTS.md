# BENCHMARK RESULTS

**Measured:** 2026-11-15 · **Commit:** `994a215` + the corpus harness in this change · **Corpus:**
`corpus/corpus.json` (7 samples, every SHA-256 pinned) · **Code under test:** RECON → NEXUS →
SPECTRE → gate, no model.

> This is the first measurement of MOBIUS on real applications. It is small, it is honest, and
> it is the only number in this repository that may be quoted as a result. Everything in
> `MODEL_BENCHMARKS.md` that is not cited from here remains **unmeasured**.

## 1. Headline

| Metric | Value | 95% CI (Wilson) | Denominator |
|---|---|---|---|
| Precision | **100.0 %** (1/1) | 20.6 % – 100.0 % | 1 flagged sample |
| Recall | **25.0 %** (1/4) | 4.6 % – 69.9 % | 4 vulnerable samples |
| Benign specificity | **100.0 %** (3/3) | 43.9 % – 100.0 % | 3 benign samples |

**Read the intervals, not the point estimates.** A precision of 100 % from a single flagged
sample is compatible with a true precision of 21 %. Three benign controls is enough to catch a
screaming false positive and nowhere near enough to establish a false-positive rate.

## 2. Per sample

| Sample | Label | Confirmed findings | Outcome |
|---|---|---|---|
| `insecurebankv2` | vulnerable | **1** | flagged |
| `mastg-uncrackable-1` | vulnerable | 0 | missed (no candidate) |
| `mastg-uncrackable-2` | vulnerable | 0 | missed (no candidate) |
| `mastg-uncrackable-3` | vulnerable | 0 | missed (no candidate) |
| `androguard-test-debug` | benign | 0 | not flagged (no candidate) |
| `androguard-testactivity` | benign | 0 | not flagged (no candidate) |
| `a2dp-volume` | benign | 0 | not flagged, **2 components in manual review** (re-measured, see §2a) |

Counts: **tp = 1, fp = 0, fn = 3, tn = 3, error = 0.**

### 2a. Re-measurement after the "no catalogued sink is NOT_DETERMINED" change

Same corpus, same pinned hashes, same harness (`python -m mobius.tools.benchmark`), before
(`f916496`) versus after (`guard/not-determined`). The headline metrics are identical, because
they count samples *flagged* (confirmed > 0). What moved is where bounded-search negatives go:

| Sample | manual_review before | manual_review after | Reason |
|---|---|---|---|
| `insecurebankv2` | 0 (5 components were `rejected` / `not-reachable`) | 5 | no catalogued sink on direct calls: not determined |
| `a2dp-volume` | 1 | 2 | the same |
| all others | 0 | 0 | no candidate |

Read-across: the earlier "correct rejection" wording for the benign samples was never a
measured correctness claim and is withdrawn; those samples simply had no candidate that
confirmed. A benign sample is "not flagged", not "proven benign". Specificity and recall remain
as measured above and carry the same wide intervals.

## 3. The one true positive, examined

```
component : com.android.insecurebankv2.ViewStatement  (activity, exported, no permission)
observation: reachability = reached, sink = webview-load, guards = []
path       : ViewStatement.onCreate(Landroid/os/Bundle;)V  →  WebView.<init>/loadUrl  (0 hops)
gate       : exported ✓  permission-absent ✓  caller_check_absent ✓  sink_reachable ✓
verdict    : confirmed, confidence 0.9
```

`ViewStatement` is one of the components InsecureBankv2 is documented as getting wrong: an
exported activity that loads content into a WebView. The gate's four clauses are each
supported by stored evidence.

**What this does not prove.** That attacker-controlled data reaches `loadUrl`. There is no
data-flow analysis in this build (R-21), so the claim is exactly "an exported activity with no
permission and no caller check calls a WebView loader", not "an attacker can inject a URL".
The report says the same thing in §3 and §6.

Five other exported components in the same app (`ChangePassword`, `DoTransfer`,
`MyBroadCastReceiver`, `PostLogin`, `TrackUserContentProvider`) had complete traversals that
found no catalogued sink. They were originally reported as "rejected"; they are now
**NOT_DETERMINED / manual review**. That outcome is a fact about the bounded search (lifecycle
roots, direct calls, catalogued sinks only), not a finding that those components are safe. Real
recall is unestablished.

## 4. Why the three crackmes were missed

All three MASTG crackmes expose exactly **one** component, and it is the launcher:

```
owasp.mstg.uncrackable1   components=1  exported=1  candidates=0  findings=0
```

The pipeline excludes a launcher from candidates because an app's own entry screen is reached
by a user tapping it, not by another app. That exclusion is deliberate (`RECON` note in
`docs/REVIEW_LOG.md` RL-005/RL-006), and here it is correct: the crackmes' documented weakness
is a **secret compiled into the app** plus root/anti-tamper checks — not an exported surface at
all.

So the 25 % recall measures **coverage of the wrong hypothesis class**, not a detector that
looked and failed. This is the most important sentence in this document:

> MOBIUS currently has one gate (`exported-component-no-permission`, MASWE-0029). A corpus
> containing other weakness classes will always depress recall, and reporting that number
> without this explanation would misrepresent both the tool and the corpus.

The honest fix is not to relabel the crackmes; it is to add gates for the weaknesses the corpus
actually contains (in-code secrets, insecure storage) before claiming recall on a mixed corpus.

## 5. What the benign controls did

- `androguard-test-debug` and `androguard-testactivity`: no findings, no manual review.
- `a2dp-volume` (14 components, 4 exported, 2 candidates): one rejection (complete traversal of
  one method found no sink) and **one manual review** — the exported receiver
  `a2dp.Vol.Widget` has no lifecycle entry point in the application code, so reachability was
  not established. It is not counted as a false positive because nothing was confirmed, but it
  is also not "clean": the report lists it under **Not determined**, which is where it belongs.

## 6. Threats to validity

| Threat | Effect |
|---|---|
| **n = 7** | Intervals are wide enough to contain almost any claim; this measures the harness, not the tool |
| **App-level labels** | "Flagged" means ≥ 1 confirmed finding, not the right one. One correct finding in an app with ten weaknesses scores the same as complete coverage |
| **Selection bias** | Three of four vulnerable samples are anti-tamper crackmes, a class this build cannot model by design |
| **Labels by the implementer** | The person who wrote the detector chose the labels. A second labeller is required before these numbers leave the project (T-036) |
| **Weak benign basis** | `a2dp-volume` is benign by absence of a documented weakness, not by audit. If a real weakness exists, precision drops to 50 % |
| **No data flow** | A confirmation is reachability, not exploitability (R-21) |
| **One dex** | Multi-dex and reflection are invisible (R-21) |

## 7. Reproduction

```bash
python3 -m venv .venv && .venv/bin/pip install -e '.[dev]'
python scripts/fetch_corpus.py --dest /tmp/mobius-corpus    # verifies every SHA-256
.venv/bin/python -m mobius.tools.benchmark /tmp/mobius-corpus/corpus.resolved.json
```

The script exits non-zero when a download does not match its pinned hash, and the benchmark
exits non-zero when a benign control is flagged. Neither behaviour is decoration: a corpus that
can change silently, or a regression that a green build hides, would make every number above
meaningless.

## 8. What may and may not be claimed

**May be claimed.** MOBIUS produced one gate-supported finding on a real, published vulnerable
application, with all four clauses evidenced and stored; it produced no confirmed finding on
three benign applications; and its verification is reproducible from pinned inputs in one
command.

**May not be claimed.** That MOBIUS measures well, that it reduces false positives relative to
any baseline, that it finds the weaknesses these apps are known for, or that its precision is
100 %. The corpus is too small, the labels too narrow, and the recall gap is a coverage gap
that this document has just made explicit.
