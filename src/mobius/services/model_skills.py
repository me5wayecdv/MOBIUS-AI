"""Domain skills conditioning for the model-backed stages (NEXUS, VERITAS).

These blocks are appended to the stage system prompts. They are CONDITIONING, not
a quality guarantee: the 2026-11-19 measurements showed small local models citing
fabricated or wrong-kind evidence despite a disciplined prompt, and the integrity
guards remain the enforcement layer. Any change here bumps the owning stage's
PROMPT_VERSION, and the persisted system_prompt_sha256 records the exact bytes
each decision was conditioned with. Real-model effect of a skills revision is
unknown until measured with the acceptance harness in live mode; a prompt change
is never reported as a measured quality improvement.

Skill content is grounded in the repository's own catalogue families
(docs/ANDROID_SOURCE_SINK_CATALOGUE.md, MASWE v1.0.0 identifiers) so the model is
steered toward the weakness shapes this build can actually evidence, instead of
generic Android security knowledge that invites unsupported claims.
"""
from __future__ import annotations

SKILLS_VERSION = "android-security-skills-v2"

# Shared citation discipline, stated once per stage prompt. The measured failure
# mode on 2026-11-19 was fabricated / wrong-kind citations, so this leads.
_CITATION_DISCIPLINE = """\
Evidence discipline (measured failure mode: fabricated or wrong-kind citations):
- Cite ONLY identifiers that appear verbatim in the supplied material. Copy them
  character-for-character; never construct, complete, translate or normalise one.
- If a claim needs evidence that was not supplied, name it as required proof; do
  not bridge the gap from general Android knowledge.
- A reachable call is may-flow evidence. Never present it as attacker control,
  exploitability, or a confirmed vulnerability.
- When the material cannot support the task, say so through the schema
  (empty hypothesis list / insufficient_evidence) instead of producing filler."""

# General Android penetration-testing frame, grounded in the repository's own
# methodology (docs/ANDROID_SECURITY_METHODOLOGY.md: MASVS v2.1.0 / MASWE v1.0.0 /
# MASTG v2.0.0, ten curated common test areas, and the six-phase flow). The
# capability boundary inside this block is load-bearing: knowing a test is not
# running it, and phases this build does not execute must surface as required
# proof for a human tester, never as results.
ANDROID_PENTEST_SKILLS = f"""\
Android penetration-testing frame ({SKILLS_VERSION}; MASVS v2.1.0, MASWE v1.0.0, MASTG v2.0.0):
- Traceability chain: MASVS control -> MASWE weakness -> MASTG test. Name the
  weakness (its MASWE id), not just the category, and name the test that would
  settle it. "MASVS-STORAGE" alone is too coarse to act on.
- Full pentest flow: reconnaissance, static analysis, dynamic analysis,
  network analysis, resilience assessment, reporting. THIS build executes
  reconnaissance, static analysis and reporting only. It does not execute
  dynamic, network or resilience phases: no runtime observation, no
  instrumentation, no traffic analysis, no tampering exercise.
- Knowing a test is not running it. When a claim needs a phase this build
  does not execute (Frida bypass, TLS interception, logcat capture, emulator
  PoC), record it as required proof for a human tester, never as a result.
- Ten common Android test areas, selected from the project methodology (a
  curated selection, not a measured frequency ranking), with the static signal
  and the validation that would change a verdict: exported component to
  privileged sink (reachability plus absent caller-permission checks); deep
  links and intents (MASWE-0029 Insecure Deep Links, MASWE-0032 Insecure
  Intents); hardcoded secret (prove
  security-context use, else informational); insecure storage (MASWE-0001:
  prove the data is sensitive); weak crypto (DES/RC4/AES-ECB, MD5/SHA1 in
  auth, static IV: establish key provenance and what it protects); cleartext/
  TLS misconfiguration (NSC cleartext, permissive TrustManager,
  onReceivedSslError proceed: name the endpoint and what flows); unsafe
  WebView (addJavascriptInterface plus setJavaScriptEnabled: show an
  attacker-influenceable content source); dynamic code loading (DexClassLoader
  family: the byte source decides severity); intent redirection
  (startActivity(getIntent()): prove an unprivileged app steers the inner
  intent); unprotected provider with path traversal (caller-controlled Uri
  reaching openFile without canonicalisation); platform misuse flags
  (debuggable in a release build, allowBackup).
- Verdict-changing validation is specific: reachability, absent caller checks,
  provenance, and whether the protected asset matters. "This could allow an
  attacker" is not analysis.
"""

VERITAS_REVIEW_SKILLS = f"""\
Android evidence-review skills ({SKILLS_VERSION}):
- Review against the deterministic gate's clauses for the finding's category:
  for exported-component-no-permission those are exported, no permission,
  caller check absent, and a catalogued sink reachable. A challenge is strongest
  when it names the specific clause the evidence does not establish.
- Know the catalogued source/sink families this build can evidence: Intent and
  deep-link inputs, Bundle/content-URI reads, clipboard reads; WebView bridge
  and file-access sinks, file/SQL/process sinks, DexClassLoader (MASWE-0029, MASWE-0030, MASWE-0032,
  MASWE-0033, MASWE-0034, MASWE-0035, MASWE-0049, MASWE-0050). Evidence outside these families
  cannot confirm a flow in this build.
- Per challenge type, probe: unsupported_claim - which gate clause lacks a
  supplied evidence statement? contradictory_evidence - do two supplied
  statements conflict on reachability, exposure or permissions?
  missing_evidence - what observation would decide the clause and is absent?
  scope_or_assumption - does the finding assume caller control, intent data
  control, or a device state the evidence does not show? alternative_explanation
  - does a guard, permission check, or non-attacker caller explain the path?
{_CITATION_DISCIPLINE}

{ANDROID_PENTEST_SKILLS}"""

NEXUS_HYPOTHESIS_SKILLS = f"""\
Android hypothesis-generation skills ({SKILLS_VERSION}):
- Prefer hypotheses in the shapes this build can actually test: an exported
  component (activity, receiver, provider, service) whose supplied observations
  suggest a reachable catalogued sink; a deep-link or Intent extra flowing
  toward a WebView, file, SQL or process sink; a DexClassLoader load reachable
  from an entry point.
- Anchor every hypothesis in the catalogued families (MASWE-0029, MASWE-0030, MASWE-0032,
  MASWE-0033, MASWE-0034, MASWE-0035, MASWE-0049, MASWE-0050) and set the maswe field from the observation's
  own metadata, not from memory of the MAS catalogue.
- State the missing link as required_evidence: the observation that would show
  attacker-controlled input reaching the sink. If no supplied observation even
  suggests the path, do not hypothesise it.
- One component per hypothesis; do not merge unrelated surfaces to look thorough.
{_CITATION_DISCIPLINE}

{ANDROID_PENTEST_SKILLS}"""
