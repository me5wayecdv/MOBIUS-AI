"""Confirmation gates.

A finding reaches ``CONFIRMED`` only by satisfying a class-specific predicate over
evidence. This module *is* that predicate (ADR-012).

Why it is the load-bearing control for two separate problems:

* **False positives.** "Exported component" is not a vulnerability - most launchers are
  exported. "MD5" is not a vulnerability - it is a cache key. Each gate names every clause
  that must hold, so the tool cannot promote a surface pattern to a finding.
* **Prompt injection.** An instruction hidden in an APK's ``strings.xml`` cannot satisfy a
  deterministic predicate. The worst a successful injection can do here is waste budget;
  it cannot manufacture a confirmed finding (docs/THREAT_MODEL.md 4, control C5).

Gates are data, not code paths, so the same declaration can be handed to a model as
``required_evidence`` *before* investigation starts. That ordering is the point: declaring
the clauses up front stops the goalposts moving after an agent has looked.
"""

from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, Callable, Mapping

from .enums import Severity


def _is_true(value: Any) -> bool:
    return value is True


def _is_false(value: Any) -> bool:
    return value is False


def _is_empty(value: Any) -> bool:
    """True when absent, None, empty string/list. Used for "no permission present"."""
    if value is None:
        return True
    if isinstance(value, str):
        return not value.strip()
    if isinstance(value, (list, tuple, set, dict)):
        return len(value) == 0
    return False


def _is_present(value: Any) -> bool:
    return not _is_empty(value)


@dataclass(frozen=True, slots=True)
class Clause:
    """One required condition. ``key`` names the attribute it reads."""

    key: str
    description: str
    predicate: Callable[[Any], bool]
    #: True when "the attribute is absent" *is* the evidence - e.g. no android:permission
    #: declared. For every other clause, an absent or None attribute means the claim was
    #: never established, which must read as missing evidence rather than as a refutation.
    absence_is_evidence: bool = False

    def evaluate(self, attributes: Mapping[str, Any]) -> bool:
        return self.predicate(attributes.get(self.key))


@dataclass(frozen=True, slots=True)
class Gate:
    category: str
    title: str
    clauses: tuple[Clause, ...]
    maswe: tuple[str, ...] = ()
    masvs: tuple[str, ...] = ()
    severity_hint: Severity = Severity.MEDIUM

    def required_evidence(self) -> tuple[str, ...]:
        """The clause keys, declared before investigation begins."""
        return tuple(c.key for c in self.clauses)


@dataclass(frozen=True, slots=True)
class GateResult:
    category: str
    passed: bool
    clauses: Mapping[str, bool]
    failed: tuple[str, ...]
    missing_attributes: tuple[str, ...]
    #: clauses that failed on a *known* value - enough to refute the hypothesis
    failed_decisively: tuple[str, ...] = ()

    def as_gate_evidence(self) -> dict[str, bool | None]:
        """Shape expected by ``Finding.gate_evidence``.

        Tri-state on purpose: ``True`` established, ``False`` refuted, ``None`` never
        established. Collapsing the third case to ``False`` made a clause no evidence was
        offered for indistinguishable from one the evidence contradicted - visible only by
        reading the finding of a real scan, where a rejected finding listed
        ``caller_check_absent: false`` although nothing had been established about it.
        """
        missing = set(self.missing_attributes)
        return {key: (None if key in missing else value) for key, value in self.clauses.items()}


_GATES: tuple[Gate, ...] = (
    Gate(
        category="exported-component-no-permission",
        title="Exported component with no permission reaches a privileged sink",
        maswe=("MASWE-0029",),
        masvs=("MASVS-PLATFORM-3",),
        severity_hint=Severity.HIGH,
        clauses=(
            Clause("exported", "Component is reachable by another app", _is_true),
            Clause("permission", "No android:permission guards it", _is_empty, absence_is_evidence=True),
            Clause(
                "caller_check_absent",
                "No runtime caller verification (checkCallingPermission / Binder.getCallingUid)",
                _is_true,
            ),
            Clause("sink_reachable", "A privileged sink is reachable from attacker input", _is_true),
        ),
    ),
    Gate(
        category="hardcoded-secret",
        title="Hardcoded credential used in a security context",
        maswe=("MASWE-0001",),
        masvs=("MASVS-STORAGE-1",),
        severity_hint=Severity.HIGH,
        clauses=(
            Clause("located", "The value exists in the artefact with a source reference", _is_true),
            Clause("format_and_entropy_ok", "Matches a known credential format and entropy floor", _is_true),
            Clause("not_placeholder", "Not a documented sample, test or placeholder value", _is_true),
            Clause(
                "used_in_security_context",
                "Consumed as an auth header, key init or signing input - not just declared",
                _is_true,
            ),
        ),
    ),
    Gate(
        category="insecure-storage",
        title="Sensitive data written to non-private storage",
        maswe=("MASWE-0001",),
        masvs=("MASVS-STORAGE-1",),
        severity_hint=Severity.MEDIUM,
        clauses=(
            Clause("insecure_location", "Written to external storage or a world-readable file", _is_true),
            Clause("write_site_confirmed", "The write site is confirmed in code, not inferred", _is_true),
            Clause("data_is_sensitive", "The data is sensitive, not a cache artefact", _is_true),
            Clause("not_encrypted_first", "Not encrypted or tokenised before the write", _is_true),
        ),
    ),
    Gate(
        category="weak-crypto",
        title="Weak primitive used to protect something that matters",
        maswe=("MASWE-001",),
        masvs=("MASVS-CRYPTO-1",),
        severity_hint=Severity.MEDIUM,
        clauses=(
            Clause("algorithm_identified", "The primitive is identified exactly", _is_true),
            Clause("algorithm_weak", "The primitive is weak for this use (DES/RC4/ECB/MD5)", _is_true),
            Clause("used_for_security_purpose", "Protects confidentiality or integrity, not a checksum", _is_true),
            Clause("key_provenance_known", "Where the key comes from is established", _is_true),
        ),
    ),
    Gate(
        category="webview-rce-surface",
        title="WebView bridge reachable with attacker-influenceable content",
        maswe=("MASWE-0029",),
        masvs=("MASVS-PLATFORM-3", "MASVS-CODE-4"),
        severity_hint=Severity.HIGH,
        clauses=(
            Clause("javascript_interface_added", "addJavascriptInterface is reachable", _is_true),
            Clause("javascript_enabled", "setJavaScriptEnabled(true) is set on the same instance", _is_true),
            Clause(
                "content_attacker_influenceable",
                "Loaded content can be influenced by an attacker, directly or via redirect",
                _is_true,
            ),
        ),
    ),
    Gate(
        category="cleartext-transport",
        title="Credentials travel over cleartext transport",
        maswe=("MASWE-005",),
        masvs=("MASVS-NETWORK-1",),
        severity_hint=Severity.HIGH,
        clauses=(
            Clause("cleartext_permitted", "The NSC or code permits cleartext", _is_true),
            Clause("non_localhost_endpoint", "A real remote endpoint is contacted", _is_true),
            Clause(
                "carries_credentials_or_tokens",
                "The payload contains a credential, token or session identifier",
                _is_true,
            ),
        ),
    ),
    Gate(
        category="exported-provider-path-traversal",
        title="Exported provider allows caller-controlled path traversal",
        maswe=("MASWE-0029",),
        masvs=("MASVS-PLATFORM-3",),
        severity_hint=Severity.HIGH,
        clauses=(
            Clause("provider_exported", "The provider is exported", _is_true),
            Clause("openfile_reachable", "openFile/openAssetFile is reachable", _is_true),
            Clause("uri_caller_controlled", "The Uri comes from the caller", _is_true),
            Clause("path_not_canonicalised", "The path is not canonicalised and prefix-checked", _is_true),
        ),
    ),
    Gate(
        category="dynamic-code-loading",
        title="Executable code loaded at runtime with no integrity check",
        maswe=("MASWE-0029",),
        masvs=("MASVS-CODE-4", "MASVS-RESILIENCE-1"),
        severity_hint=Severity.HIGH,
        clauses=(
            Clause("loader_used", "A DexClassLoader/InMemoryDexClassLoader is instantiated", _is_true),
            Clause(
                "source_is_network_or_external",
                "The byte source is a network response or external storage (data flow, not API presence)",
                _is_true,
            ),
            Clause(
                "no_integrity_check",
                "No signature or digest check gates the load",
                _is_true,
            ),
        ),
    ),
    Gate(
        category="implicit-intent-sensitive-data",
        title="Sensitive data broadcast or sent via an implicit intent",
        maswe=("MASWE-0029",),
        masvs=("MASVS-PLATFORM-3",),
        severity_hint=Severity.MEDIUM,
        clauses=(
            Clause("sensitive_extra_present", "A sensitive value is placed in the intent", _is_true),
            Clause("implicit_intent", "The intent is implicit", _is_true),
            Clause("no_explicit_target", "No package or explicit component is set", _is_true),
        ),
    ),
    Gate(
        category="deeplink-unvalidated-input",
        title="Deep link parameter reaches a sensitive sink unvalidated",
        maswe=("MASWE-0029",),
        masvs=("MASVS-PLATFORM-3",),
        severity_hint=Severity.HIGH,
        clauses=(
            Clause("deeplink_entry", "A deep link entry point exists", _is_true),
            Clause("param_reaches_sink", "Its parameter flows to a sensitive sink", _is_true),
            Clause("no_validation_on_path", "No validation or allowlist applies on that path", _is_true),
        ),
    ),
)

GATES: Mapping[str, Gate] = MappingProxyType({g.category: g for g in _GATES})


class UnknownGate(Exception):
    """Raised when a category has no gate. Better than silently passing."""


def get_gate(category: str) -> Gate:
    try:
        return GATES[category]
    except KeyError as exc:
        raise UnknownGate(
            f"no gate defined for category {category!r}; "
            f"known categories: {sorted(GATES)}"
        ) from exc


def required_evidence(category: str) -> tuple[str, ...]:
    """Clauses to declare on a Hypothesis *before* investigation starts."""
    return get_gate(category).required_evidence()


def evaluate(category: str, attributes: Mapping[str, Any]) -> GateResult:
    """Evaluate every clause. All must pass; there is no partial credit.

    Missing attributes are reported separately from failed ones. The distinction matters
    for the UI: "we did not establish this" is a request for more evidence, while "this is
    false" refutes the hypothesis. Collapsing them would make the tool look certain about
    things it never checked.
    """
    gate = get_gate(category)
    results: dict[str, bool] = {}
    missing: list[str] = []
    for clause in gate.clauses:
        results[clause.key] = clause.evaluate(attributes)
        absent = clause.key not in attributes or (
            attributes.get(clause.key) is None and not clause.absence_is_evidence
        )
        if absent:
            missing.append(clause.key)

    failed = tuple(k for k, v in results.items() if not v)
    # A clause that failed on a value we actually have refutes the hypothesis. A clause that
    # "failed" only because its attribute was never established does not, and must not be
    # reported as if it did.
    decisive = tuple(k for k in failed if k not in missing)
    return GateResult(
        category=category,
        passed=not failed,
        clauses=results,
        failed=failed,
        missing_attributes=tuple(missing),
        failed_decisively=decisive,
    )


def all_categories() -> tuple[str, ...]:
    return tuple(GATES)
