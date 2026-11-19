"""Hardcoded-secret candidate detection with register-level use evidence.

Prototype scope (isolated, feeds the existing ``hardcoded-secret`` gate):

* Whole-code traversal: every method's const-string literals are examined, not
  only exported entry points.
* Candidates come from screening signals (label extraction, known credential
  formats, entropy) OR from use evidence itself: a literal that flows into key
  material or an external-input comparison is a candidate even when no
  screening signal fires. Screening never establishes evidence.
* Use evidence comes from a bounded block-aware register provenance scan
  (basic-block CFG, union join, kill-on-unmodelled-writes). Two tiers:
  - ``key-material-argument`` (confirmation-grade): the literal, converted via
    getBytes/toCharArray, reaches the key/password argument position of
    SecretKeySpec.<init> (byte[] key), PBEKeySpec.<init> (char[] password) or
    KeyStore.load (char[] password). A string arriving UNCONVERTED at those
    APIs is an algorithm/spec parameter ("AES"), never evidence. IVs, salts,
    digested payloads and keystore streams are deliberately excluded: they are
    not automatically secret.
  - ``access-comparison-suspect`` (review-only): the literal is compared
    (equals/equalsIgnoreCase/contentEquals/compareTo) against external-input
    provenance and the result feeds a conditional branch. This is NOT
    confirmation: UI routing, dispatch and form validation share the shape.
    It raises the candidate into manual review with the chain attached.
* ``used_in_security_context`` is set True ONLY on key-material evidence.
  Otherwise the attribute is absent, the gate reports missing evidence, and
  the finding lands in manual review. Intent.getAction() is excluded as an
  input source (dispatch metadata). Method names contribute nothing.
* ``format_and_entropy_ok`` is computed genuinely (known format, or entropy
  >= floor with charset diversity and length >= 20). A flow-evidenced value
  that fails it reports False; the gate, not the detector, decides what that
  means. Entropy is screening, not secrecy.

Known limitations, reported with results: one bounded pass per block (cycles
and unresolved edges mark the method flow-incomplete and absence of evidence
is NOT claimed there); no inter-procedural flow; statics set in <clinit>
appear there; resource-loaded values (R.string) are not const-strings;
obfuscated or split values reassemble only through the propagation whitelist.
"""
from __future__ import annotations

import math
import re
import dataclasses
from collections import deque
from dataclasses import dataclass, field
from typing import Iterable, Mapping, Sequence

from ..adapters.dex import CodeIndex
from .providers import parameter_registers
from .reachability import MethodRef

# -- screening signals (candidate admission only, never evidence) --------------

_LABEL = re.compile(
    r"(?:api[-_ ]?key|secret|token|password|passwd|pwd|credential|auth[-_ ]?key|"
    r"private[-_ ]?key|client[-_ ]?secret|access[-_ ]?key)\s*[:=]\s*(\"?)([^\s\"\\]{4,})\1",
    re.IGNORECASE,
)

_KNOWN_FORMATS: tuple[tuple[str, re.Pattern], ...] = (
    ("aws-access-key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("stripe-secret", re.compile(r"\b[sr]k_(live|test)_[0-9A-Za-z]{16,}\b")),
    ("github-token", re.compile(r"\b(ghp|gho|ghu|ghs|ghr)_[0-9A-Za-z]{36,}\b")),
    ("github-fine-grained", re.compile(r"\bgithub_pat_[0-9A-Za-z_]{40,}\b")),
    ("google-api-key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35,}\b")),
    ("slack-token", re.compile(r"\bxox[baprs]-[0-9A-Za-z\-]{10,}\b")),
    ("jwt", re.compile(r"\beyJ[0-9A-Za-z_\-]{10,}\.[0-9A-Za-z_\-]{10,}\.[0-9A-Za-z_\-]{5,}\b")),
    ("private-key-block", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
    ("generic-bearer", re.compile(r"\bBearer\s+[0-9A-Za-z._\-]{16,}\b")),
)

_NAMESPACED_CONSTANT = re.compile(r"^[a-z][a-z0-9_]*(\.[a-z0-9_]+)+\.[A-Z][A-Z0-9_]*$")
# Fully-qualified-class-name shape (android.support.v4.media.IFoo$Stub): dotted
# identifier segments ending in a CamelCase segment - interface descriptors, not keys.
_FQCN = re.compile(r"^([a-z][a-z0-9_]*\.)+[A-Z][A-Za-z0-9_$]*$")

_PLACEHOLDER = re.compile(
    r"^(?:example|sample|test|dummy|changeme|change[-_ ]?me|placeholder|todo|fixme|"
    r"your[-_a-z]*|insert[-_a-z]*|xxx+|\*+|0{3,}|1234+|abcd|qwerty|null|none|nil|false|true)$",
    re.IGNORECASE,
)

_MIN_LEN, _MAX_LEN = 8, 512
#: All-unique 20-char strings top out at log2(20) ~= 4.32; the floor sits just below
#: that so genuinely random keys pass and structured constants fall to the other filters.
_ENTROPY_FLOOR = 4.2
_ENTROPY_MIN_LEN = 20

# -- flow model -----------------------------------------------------------------

# The flow engine lives in .flow; re-exported here for existing callers.
from .flow import (  # noqa: F401
    FlowBlock,
    FlowEvidence,
    MethodFlowScan,
    SInstruction,
    flow_scan_from_androguard,
    scan_method_flow,
)



# -- candidates -----------------------------------------------------------------

def _shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts: dict[str, int] = {}
    for char in value:
        counts[char] = counts.get(char, 0) + 1
    n = len(value)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _charset_classes(value: str) -> int:
    return sum((
        any(c.islower() for c in value),
        any(c.isupper() for c in value),
        any(c.isdigit() for c in value),
        any(not c.isalnum() for c in value),
    ))


def format_and_entropy_ok(value: str) -> tuple[bool, str]:
    """Genuine format/entropy assessment of a candidate value (screening only)."""
    for name, pattern in _KNOWN_FORMATS:
        if pattern.search(value):
            return True, f"known-format:{name}"
    stripped = value.strip()
    if (len(stripped) >= _ENTROPY_MIN_LEN and _shannon_entropy(stripped) >= _ENTROPY_FLOOR
            and _charset_classes(stripped) >= 3):
        return True, f"entropy:{_shannon_entropy(stripped):.2f}"
    return False, f"no known format; entropy {_shannon_entropy(stripped):.2f}, length {len(stripped)}"


def _screen(literal: str) -> tuple[str, tuple[str, ...]] | None:
    """Screening-signal candidacy. Never evidence."""
    labeled = [(m.group(2), ("labeled-credential",)) for m in _LABEL.finditer(literal)]
    if labeled:
        return max(labeled, key=lambda item: len(item[0]))
    for name, pattern in _KNOWN_FORMATS:
        match = pattern.search(literal)
        if match:
            return match.group(0), (f"known-format:{name}",)
    stripped = literal.strip()
    if _MIN_LEN <= len(stripped) <= _MAX_LEN and " " not in stripped and "\n" not in stripped:
        entropy = _shannon_entropy(stripped)
        if len(stripped) >= _ENTROPY_MIN_LEN and entropy >= _ENTROPY_FLOOR \
                and _charset_classes(stripped) >= 3:
            if _NAMESPACED_CONSTANT.match(stripped) or _FQCN.match(stripped):
                return None
            return stripped, (f"entropy:{entropy:.2f}",)
    return None


def _is_placeholder(value: str) -> bool:
    if _PLACEHOLDER.match(value):
        return True
    # Keyboard walks and single-character repeats survive the regex list.
    return len(set(value)) <= 2


@dataclass(frozen=True, slots=True)
class SecretCandidate:
    method: MethodRef
    literal: str
    value: str
    basis: tuple[str, ...]
    evidence: tuple[FlowEvidence, ...] = ()
    flow_complete: bool = True

    @property
    def used_in_security_context(self) -> bool | None:
        """True ONLY on key-material evidence. Comparison-suspect evidence is
        reported for review but never establishes security-context use."""
        if any(e.kind == "key-material-argument" for e in self.evidence):
            return True
        return None


def _param_slots(descriptor: str) -> list[int] | None:
    """Parameter slot widths from a compact JVM descriptor; wide types (J, D)
    take two. None when the descriptor cannot be parsed (never guessed)."""
    try:
        inside = descriptor[descriptor.index("(") + 1:descriptor.index(")")]
    except (ValueError, IndexError):
        return None
    widths: list[int] = []
    i = 0
    while i < len(inside):
        c = inside[i]
        if c == "[":
            j = i
            while j < len(inside) and inside[j] == "[":
                j += 1
            if j >= len(inside):
                return None
            if inside[j] == "L":
                end = inside.find(";", j)
                if end < 0:
                    return None
                i = end + 1
            else:
                i = j + 1
            widths.append(1)
        elif c == "L":
            end = inside.find(";", i)
            if end < 0:
                return None
            i = end + 1
            widths.append(1)
        elif c in "JD":
            widths.append(2)
            i += 1
        elif c in "ZBSCIF":
            widths.append(1)
            i += 1
        else:
            return None
    return widths


def detect_hardcoded_secrets(
    index: CodeIndex,
    flows: Mapping[MethodRef, Sequence[FlowBlock]] | None = None,
    frame_info: Mapping[MethodRef, tuple[int, bool]] | None = None,
) -> list[SecretCandidate]:
    """Surface hardcoded-secret candidates with their gate-attribute evidence.

    With ``flows`` provided, use evidence comes from the register scan. Without
    them no evidence can be produced and every candidate stays manual-review.
    """
    candidates: list[SecretCandidate] = []
    # Class-level field seeding: scan constructors (<init>/<clinit>) first and
    # seed sibling scans with the fields they initialise, so a literal stored
    # in a constructor and consumed in another method still carries provenance.
    # If any constructor scan is incomplete, sibling scans inherit incomplete
    # (absence claims would rest on partial field knowledge).
    ctor_fields: dict[str, dict] = {}
    ctor_complete: dict[str, bool] = {}
    if flows:
        classes = {m.class_name for m in flows}
        for cls in classes:
            summary: dict = {}
            complete_all = True
            for m in sorted((m for m in flows if m.class_name == cls and m.name in ("<init>", "<clinit>")), key=str):
                cscan = scan_method_flow(flows[m])
                complete_all = complete_all and cscan.complete
                for ref, origins in cscan.field_summary.items():
                    summary.setdefault(ref, set()).update(origins)
            ctor_fields[cls] = {ref: frozenset(o) for ref, o in summary.items()}
            ctor_complete[cls] = complete_all
    # Evidence found in sibling scans for literals declared in a constructor is
    # merged onto that literal's candidate below.
    deferred: dict[str, dict[str, list]] = {}  # class -> literal -> evidence list
    deferred_by_method: dict[MethodRef, dict[str, list]] = {}  # caller -> literal -> evidence
    deferred_incomplete: set[tuple[str, str]] = set()  # (class, callee) one-hop incompletes
    incomplete_callers: set[MethodRef] = set()  # callers whose chained scan was partial
    deferred_fielddep: set[tuple[str, str]] = set()  # (class, value) field-carried evidence
    pending: dict[MethodRef, tuple] = {}
    for method in sorted(set(index.strings) | (set(flows) if flows else set()), key=str):
        if flows and method in flows:
            seed = ctor_fields.get(method.class_name) or None
            scan = scan_method_flow(flows[method], entry_fields=seed)
            if scan.complete and method.name not in ("<init>", "<clinit>") and not ctor_complete.get(method.class_name, True):
                scan = dataclasses.replace(scan, complete=False)
        else:
            scan = None
        flow_evidence = scan.evidence if scan else {}
        pending[method] = (scan, flow_evidence)
        if method.name in ("<init>", "<clinit>"):
            continue
        for value, evs in flow_evidence.items():
            deferred.setdefault(method.class_name, {}).setdefault(value, []).extend(
                FlowEvidence(e.kind, f"[in {method.class_name}.{method.name}] {e.detail}")
                for e in evs)
            if scan is not None and scan.field_dependent:
                deferred_fielddep.add((method.class_name, value))
        # One-hop internal-call chaining: key-material/literal/external origins
        # passed into a same-class method present in flows are scanned one hop
        # deep with caller-argument seeding. EXACT dispatch only (invoke-static,
        # invoke-direct; /range never normalised here): virtual/interface calls
        # can resolve to overrides and are never chained. Parameter registers
        # come from the OWNING method's real registers_size via frame_info
        # (providers.parameter_registers); without it the call is not chained.
        # No recursion beyond one hop.
        if scan is not None and method.name not in ("<init>", "<clinit>"):
            for call in scan.calls:
                if (call.invoke_descriptor is None
                        or call.opcode not in ("invoke-static", "invoke-direct")):
                    continue
                # flow map keys may carry androguard's spaced descriptor form;
                # the call record's is normalised compact. Match on both.
                want_desc = re.sub(r"\s+", "", call.invoke_descriptor)
                callee = next(
                    (m for m in flows
                     if m.class_name == call.invoke_class[1:-1].replace("/", ".")
                     and m.name == call.invoke_method
                     and re.sub(r"\s+", "", m.descriptor) == want_desc),
                    None)
                if callee is None or callee.class_name != method.class_name or callee == method:
                    continue
                tracked = ("lit", "keybytes", "ext")
                if not any(o and o[0] in tracked for origins in call.arg_origins for o in origins):
                    continue
                widths = _param_slots(call.invoke_descriptor)
                if widths is None or frame_info is None or callee not in frame_info:
                    continue  # no owning-method register metadata: honest unsupported
                registers_size, callee_static = frame_info[callee]
                if call.is_static != callee_static:
                    continue  # call-site vs owning-method staticness disagree: never guess
                params = parameter_registers(call.invoke_descriptor, registers_size, callee_static)
                if not params or len(params) != len(widths):
                    continue  # never guess the parameter base
                words = call.arg_origins
                this_words = 0 if call.is_static else 1
                if len(words) != this_words + sum(widths):
                    continue  # register-word count mismatch: never guess
                entry_state: dict[int, frozenset] = {}
                if this_words:
                    entry_state[params[0] - 1 if params[0] > 0 else 0] = words[0]
                    words = words[1:]
                cursor = 0
                for reg, width in zip(params, widths):
                    entry_state[reg] = words[cursor]
                    cursor += width  # wide values: seed the LOW word, skip the high
                callee_scan = scan_method_flow(flows[callee], entry_state=entry_state,
                                               entry_fields=ctor_fields.get(callee.class_name) or None)
                if not callee_scan.complete or not scan.complete:
                    deferred_incomplete.add((method.class_name, callee.name))
                    incomplete_callers.add(method)
                if callee_scan.field_dependent or scan.field_dependent:
                    for value in callee_scan.evidence:
                        deferred_fielddep.add((method.class_name, value))
                for value, evs in callee_scan.evidence.items():
                    prefixed = [
                        FlowEvidence(e.kind,
                                     f"[via internal call {callee.name} at offset {call.offset} "
                                     f"in {method.class_name}.{method.name}] {e.detail}")
                        for e in evs]
                    deferred.setdefault(method.class_name, {}).setdefault(value, []).extend(prefixed)
                    deferred_by_method.setdefault(method, {}).setdefault(value, []).extend(prefixed)
    for method in sorted(set(index.strings), key=str):
        scan, flow_evidence = pending.get(method, (None, {}))
        # literals declared in a constructor also carry evidence found in
        # sibling methods of the same class; literals declared in an ordinary
        # caller carry the evidence found in their chained callees
        extra: dict[str, list] = {}
        if method.name in ("<init>", "<clinit>"):
            extra.update(deferred.get(method.class_name, {}))
        for value, evs in deferred_by_method.get(method, {}).items():
            extra.setdefault(value, []).extend(evs)
        if extra:
            merged_evidence: dict[str, list] = {k: list(v) for k, v in flow_evidence.items()}
            for value, evs in extra.items():
                merged_evidence.setdefault(value, []).extend(evs)
            flow_evidence = {k: tuple(v) for k, v in merged_evidence.items()}
        admitted: dict[str, tuple[str, tuple[str, ...]]] = {}
        for literal in index.strings[method]:
            extracted = _screen(literal)
            if extracted is not None:
                value, basis = extracted
                if not _is_placeholder(value):
                    admitted.setdefault(value, (literal, basis))
        for value in flow_evidence:
            if value not in admitted and not _is_placeholder(value):
                literal = next((lit for lit in index.strings[method] if lit == value), value)
                admitted[value] = (literal, ("flow-evidenced-literal",))
        for value, (literal, basis) in admitted.items():
            evid = flow_evidence.get(value, ())
            complete = True if scan is None else scan.complete
            if method.name in ("<init>", "<clinit>") and any(
                    cls == method.class_name for cls, _ in deferred_incomplete):
                complete = False  # merged one-hop evidence rests on an incomplete scan
            if method in incomplete_callers:
                complete = False  # this caller's own or its callee's scan was partial
            if (method.class_name, value) in deferred_fielddep:
                # Evidence arrived through field-carried provenance: sibling
                # writes/setters/aliases/static-init ordering are not modelled,
                # so this stays candidate-only, never absence-backed.
                complete = False
            if scan is not None and scan.field_dependent:
                complete = False
            candidates.append(SecretCandidate(
                method=method, literal=literal, value=value,
                basis=(*basis, *(f"{e.kind}: {e.detail}" for e in evid)),
                evidence=evid,
                flow_complete=complete,
            ))
    return candidates


def gate_attributes(candidate: SecretCandidate) -> dict[str, object]:
    """Attributes for the existing ``hardcoded-secret`` gate. Missing evidence stays
    missing (None is never written - absent keys read as not established)."""
    ok, reason = format_and_entropy_ok(candidate.value)
    attributes: dict[str, object] = {
        "located": True,
        "format_and_entropy_ok": ok,
        "format_and_entropy_basis": reason,
        "not_placeholder": not _is_placeholder(candidate.value),
    }
    if candidate.used_in_security_context is True:
        attributes["used_in_security_context"] = True
    if any(e.kind == "access-comparison-suspect" for e in candidate.evidence):
        attributes["access_comparison_suspect"] = True  # review signal, NOT use evidence
    if not candidate.flow_complete:
        attributes["flow_incomplete"] = True
    return attributes


def describe(candidate: SecretCandidate) -> dict[str, object]:
    import hashlib
    return {
        "method": str(candidate.method),
        "value_sha256_8": hashlib.sha256(candidate.value.encode()).hexdigest()[:8],
        "value_length": len(candidate.value),
        "basis": list(candidate.basis),
        "flow_complete": candidate.flow_complete,
    }
