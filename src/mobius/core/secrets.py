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
* ``used_in_security_context`` is set True ONLY on key-material evidence
  (direct, or a may-depend route to a key argument through one closed-world
  return-transform hop plus one exact static/direct sink hop - reported as
  ``key-material-argument-derived``; the transform's output bytes are
  unmodelled and no decoded key value is ever claimed). Otherwise the
  attribute is absent, the gate reports missing evidence, and the finding
  lands in manual review. Intent.getAction() is excluded as an input source
  (dispatch metadata). Method names contribute nothing.
* ``format_and_entropy_ok`` is computed genuinely (known format, or entropy
  >= floor with charset diversity and length >= 20). A flow-evidenced value
  that fails it reports False; the gate, not the detector, decides what that
  means. Entropy is screening, not secrecy. EXCEPTION: when key-material
  evidence establishes the key role, the credential-shape predicate is
  inapplicable (encoded keys are arbitrary bytes), so the attribute is left
  absent - the gate reports it missing, not refuted - and a
  ``format_assessment`` attribute explains why. No format rule is relaxed to
  make any sample pass.

Known limitations, reported with results: one bounded pass per block (cycles
and unresolved edges mark the method flow-incomplete and absence of evidence
is NOT claimed there); inter-procedural flow is limited to one exact
static/direct hop (same-class) plus, for the derived-key route only, one
closed-world pure return-transform hop and one exact static/direct sink hop
(cross-class allowed there); statics set in <clinit> appear there;
resource-loaded values (R.string) are not const-strings; obfuscated or split
values reassemble only through the propagation whitelist.
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
    CallRecord,
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
        reported for review but never establishes security-context use.

        A True resting on DERIVED-only evidence is a may-depend route claim
        (transform output unmodelled), weaker than a True resting on direct
        evidence: the per-evidence distinction is carried by the evidence
        kinds and by ``gate_attributes`' ``security_use_basis``."""
        if any(e.kind in ("key-material-argument", "key-material-argument-derived")
               for e in self.evidence):
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


# -- derived-key route ---------------------------------------------------------

#: Calls allowed inside a closed-world pure transform: value-only functions of
#: their receiver/arguments. Anything else (field access, external input, app
#: code, System/Time/Random, ...) fails the purity proof.
_PURE_TRANSFORM_APIS: frozenset[tuple[str, str]] = frozenset({
    ("Ljava/lang/String;", "length"),
    ("Ljava/lang/String;", "charAt"),
    ("Ljava/lang/Character;", "digit"),
    ("Ljava/lang/String;", "getBytes"),
    ("Ljava/lang/String;", "toCharArray"),
})

#: Opcode families a pure transform may contain. Register arithmetic, moves,
#: branches, array construction/element access and small constants only.
_PURE_OP_PREFIXES = (
    "const/", "const-wide", "const-high16",
    "move", "if-", "goto", "return", "nop",
    "array-length", "new-array", "aget", "aput", "check-cast",
    "add-", "sub-", "mul-", "div-", "rem-", "and-", "or-", "xor-",
    "shl-", "shr-", "ushr-", "neg-", "not-", "int-to-", "long-to-",
    "cmp", "instance-of",
)

#: Never pure: field access, new literals, constant array payloads, exception
#: moves, object construction, monitors, switches, throws.
_PURE_REJECT_PREFIXES = (
    "iput", "sput", "iget", "sget", "const-string", "fill-array",
    "move-exception", "new-instance", "throw", "monitor-",
    "packed-switch", "sparse-switch",
)


def _index_flows(
    flows: Mapping[MethodRef, object],
) -> tuple[dict[str, list[MethodRef]], dict[tuple[str, str, str], list[MethodRef]]]:
    """One-pass lookup indexes over the flow map.

    Returns (constructors by class, methods by normalised
    (class, name, descriptor) key). Bucket order preserves the mapping's
    iteration order, so first-match and unique-match lookups return exactly
    the element a repeated full scan would find. Pure re-indexing: matching
    predicates, verdict logic, guards and ordering are unchanged.
    """
    ctors: dict[str, list[MethodRef]] = {}
    by_key: dict[tuple[str, str, str], list[MethodRef]] = {}
    for ref in flows:
        if ref.name in ("<init>", "<clinit>"):
            ctors.setdefault(ref.class_name, []).append(ref)
        key = (ref.class_name, ref.name, re.sub(r"\s+", "", ref.descriptor))
        by_key.setdefault(key, []).append(ref)
    return ctors, by_key


def _resolve_callee(
    flows: Mapping[MethodRef, object],
    invoke_class: str,
    invoke_method: str,
    invoke_descriptor: str,
    flow_index: Mapping[tuple[str, str, str], Sequence[MethodRef]] | None = None,
) -> MethodRef | None:
    """Exactly one normalised (class, name, descriptor) match, else None.

    Zero matches (framework/external code, missing flows) and ambiguous matches
    (duplicate definitions) both fail closed: never guessed. ``flow_index`` is
    an optional prebuilt (class, name, descriptor) -> refs index (see
    ``_index_flows``); without it the flow map is scanned directly.
    """
    want_desc = re.sub(r"\s+", "", invoke_descriptor)
    if flow_index is not None:
        matches = list(flow_index.get(
            (invoke_class[1:-1].replace("/", "."), invoke_method, want_desc), ()))
    else:
        matches = [
            m for m in flows
            if m.class_name == invoke_class[1:-1].replace("/", ".")
            and m.name == invoke_method
            and re.sub(r"\s+", "", m.descriptor) == want_desc
        ]
    if len(matches) != 1:
        return None
    return matches[0]


def _transform_closed_world(blocks: Sequence[FlowBlock]) -> bool:
    """Closed-world syntactic purity proof for a return-transform.

    Every instruction must be register arithmetic, moves, branches, array
    element access, small constants, or an allowlisted pure call; no field
    access, no other calls, no new literals, no exception moves. Exactly one
    return instruction. This bounds SOURCES (nothing outside the parameters
    can enter); it says nothing about whether the return depends on them -
    that is `_return_content_tainted`.
    """
    returns = 0
    for block in blocks:
        for ins in block.instructions:
            if ins.unsupported:
                return False
            op = ins.opcode
            if op.startswith(_PURE_REJECT_PREFIXES):
                return False
            if op.startswith("invoke-"):
                if (ins.invoke_class, ins.invoke_method) not in _PURE_TRANSFORM_APIS:
                    return False
            elif op.startswith(("return-object", "return", "return-void", "return-wide")):
                returns += 1
            elif not op.startswith(_PURE_OP_PREFIXES):
                return False
    return returns == 1


def _return_content_tainted(
    blocks: Sequence[FlowBlock],
    seed_regs: frozenset[int] | set[int],
) -> bool:
    """Bounded forward content-dependence proof for a pure transform.

    May-taint fixpoint over the callee CFG with two lattices: scalar register
    taint and array-content taint, union join at block entries. Seeds are the
    literal-carrying parameter registers. Moves, arithmetic, casts and the
    allowlisted invokes propagate (an invoke taints its result when ANY
    register at the call is tainted); a write of untainted data KILLS the
    register; a tainted array SIZE never taints the array's contents
    (new-array drops taint); aput of tainted data taints the array, aget from
    a tainted array taints the destination. True only when the single return
    register is tainted at the fixpoint. Bounded worklist; over the bound the
    answer is not proven (fail closed).

    This is a MAY-taint union over paths: an OVER-approximation of content
    dependence. A tainted return means the return MAY depend on the literal's
    content - one contributing path is enough, another path may return a
    constant, weak updates never untaint overwritten arrays, and lengths never
    carry content taint. An untainted return suppresses the evidence (fail
    closed); a tainted one is may-depend evidence, never proof of derivation.
    """
    by_start = {b.start: b for b in blocks}
    if not by_start or len(by_start) != len(blocks):
        return False
    entry = min(by_start)
    in_reg: dict[int, set[int]] = {entry: set(seed_regs)}
    in_arr: dict[int, set[int]] = {entry: set()}

    def transfer(
        block: FlowBlock, reg_in: set[int], arr_in: set[int]
    ) -> tuple[set[int], set[int], bool | None]:
        reg = set(reg_in)
        arr = set(arr_in)
        pending = False
        ret: bool | None = None
        for ins in block.instructions:
            op = ins.opcode
            regs = ins.registers
            if op.startswith("invoke-"):
                # String.length is allowlisted for purity (bounded sources) but
                # its result is the LENGTH, not content: it never propagates
                # content taint. A key that "depends" only on the literal's
                # length does not depend on the literal.
                is_length = (ins.invoke_class, ins.invoke_method) == (
                    "Ljava/lang/String;", "length")
                pending = not is_length and any(r in reg or r in arr for r in regs)
            elif op.startswith("move-result"):
                if regs:
                    if pending:
                        reg.add(regs[0])
                    else:
                        reg.discard(regs[0])
                    arr.discard(regs[0])
                pending = False
            elif op.startswith("move"):
                if len(regs) >= 2:
                    if regs[1] in reg:
                        reg.add(regs[0])
                    else:
                        reg.discard(regs[0])
                    if regs[1] in arr:
                        arr.add(regs[0])
                    else:
                        arr.discard(regs[0])
                elif regs:
                    reg.discard(regs[0])
                    arr.discard(regs[0])
            elif op.startswith("const"):
                if regs:
                    reg.discard(regs[0])
                    arr.discard(regs[0])
            elif op.startswith("new-array"):
                # Fresh contents: a tainted size must not taint contents.
                if regs:
                    reg.discard(regs[0])
                    arr.discard(regs[0])
            elif op.startswith("array-length"):
                # A length read is not content provenance, even from a tainted
                # array: the result never carries content taint.
                if regs:
                    reg.discard(regs[0])
            elif op.startswith("aput"):
                if len(regs) >= 2 and (regs[0] in reg or regs[0] in arr):
                    arr.add(regs[1])
            elif op.startswith("aget"):
                if regs:
                    if len(regs) >= 2 and regs[1] in arr:
                        reg.add(regs[0])
                    else:
                        reg.discard(regs[0])
                    arr.discard(regs[0])
            elif op.startswith("check-cast"):
                pass  # in-place: provenance untouched
            elif op.startswith(("return-object", "return", "return-wide")):
                ret = bool(regs) and (regs[0] in reg or regs[0] in arr)
            elif op.startswith(("if-", "goto", "nop", "return-void")):
                pass
            else:
                # Remaining allowlisted arithmetic/conversion ops, dest-first.
                if regs:
                    if any(r in reg or r in arr for r in regs[1:]):
                        reg.add(regs[0])
                    else:
                        reg.discard(regs[0])
                    arr.discard(regs[0])
        return reg, arr, ret

    worklist = deque([entry])
    queued = {entry}
    cap = max(64, 8 * len(by_start))
    passes = 0
    while worklist:
        passes += 1
        if passes > cap:
            return False  # unbounded: not proven
        start = worklist.popleft()
        queued.discard(start)
        block = by_start[start]
        reg, arr, _ = transfer(block, in_reg.get(start, set()), in_arr.get(start, set()))
        for succ in block.successors:
            if succ not in by_start:
                continue
            merged_reg = in_reg.get(succ, set()) | reg
            merged_arr = in_arr.get(succ, set()) | arr
            if merged_reg != in_reg.get(succ, set()) or merged_arr != in_arr.get(succ, set()):
                in_reg[succ] = merged_reg
                in_arr[succ] = merged_arr
                if succ not in queued:
                    worklist.append(succ)
                    queued.add(succ)
    # Fixpoint reached: evaluate the single return with the stable in-states.
    for start, block in by_start.items():
        _, _, ret = transfer(block, in_reg.get(start, set()), in_arr.get(start, set()))
        if ret is not None:
            return ret
    return False


def _derived_transform_literal(
    producer: CallRecord,
    flows: Mapping[MethodRef, Sequence[FlowBlock]],
    frame_info: Mapping[MethodRef, tuple[int, bool]] | None,
    flow_index: Mapping[tuple[str, str, str], Sequence[MethodRef]] | None = None,
) -> str | None:
    """Literal with a may-depend route through a pure return-transform, else None.

    ``producer`` is the invoke whose return value is consumed downstream. The
    route is reportable only when the producer is an exactly-resolved
    invoke-static/direct, exactly one literal/keybytes value enters it (no
    external, field or other-call-result mixing), its callee passes the
    closed-world purity proof, and the bounded may-taint fixpoint shows the
    return MAY depend on the literal-carrying parameter's content. One
    transform hop; no recursion. The result is may-depend evidence, never a
    proof of the decoded value.
    """
    if (producer.invoke_descriptor is None
            or producer.opcode not in ("invoke-static", "invoke-direct")):
        return None
    seen = [o for origins in producer.arg_origins for o in origins if o]
    values = {o[1] for o in seen if o[0] in ("lit", "keybytes")}
    if len(values) != 1:
        return None  # none, or several literals: ambiguous derivation, never guess
    if any(o[0] not in ("lit", "keybytes", "const") for o in seen):
        return None  # external input, field or prior call-result mixing: fail closed
    value = next(iter(values))
    if frame_info is None:
        return None
    callee = _resolve_callee(flows, producer.invoke_class, producer.invoke_method,
                             producer.invoke_descriptor, flow_index=flow_index)
    if callee is None or callee not in frame_info:
        return None
    registers_size, callee_static = frame_info[callee]
    if producer.is_static != callee_static:
        return None  # call-site vs owning-method staticness disagree: never guess
    widths = _param_slots(producer.invoke_descriptor)
    if widths is None:
        return None
    params = parameter_registers(producer.invoke_descriptor, registers_size, callee_static)
    if not params or len(params) != len(widths):
        return None
    words = producer.arg_origins
    this_words = 0 if producer.is_static else 1
    if len(words) != this_words + sum(widths):
        return None  # register-word count mismatch: never guess
    lit_words = {i for i, origins in enumerate(words)
                 if any(o and o[0] in ("lit", "keybytes") for o in origins)}
    lit_param_regs: set[int] = set()
    cursor = this_words
    for reg, width in zip(params, widths):
        if any(cursor <= i < cursor + width for i in lit_words):
            lit_param_regs.add(reg)
        cursor += width
    if not lit_param_regs:
        return None
    if not _transform_closed_world(flows[callee]):
        return None
    if not _return_content_tainted(flows[callee], frozenset(lit_param_regs)):
        return None
    return value


def detect_hardcoded_secrets(
    index: CodeIndex,
    flows: Mapping[MethodRef, Sequence[FlowBlock]] | None = None,
    frame_info: Mapping[MethodRef, tuple[int, bool]] | None = None,
    dex_complete: bool | None = None,
) -> list[SecretCandidate]:
    """Surface hardcoded-secret candidates with their gate-attribute evidence.

    With ``flows`` provided, use evidence comes from the register scan. Without
    them no evidence can be produced and every candidate stays manual-review.

    ``dex_complete`` is the scan-completeness precondition for the derived
    (pure-transform) tier only: True when the caller's DEX ledger is fully
    parsed with no duplicate or ambiguous classes (e.g.
    ``mobius.adapters.provider_payload.dex_ledger_complete``). None means
    unknown and suppresses the derived tier exactly like False. The direct
    tier never consults it.

    Screening note: candidate admission is role-based, not format-based; the
    placeholder check covers only trivial strings (repeated characters,
    short lexicon words). The size of the resulting manual-review workload
    on a large corpus is unmeasured.
    """
    candidates: list[SecretCandidate] = []
    # Class-level field seeding: scan constructors (<init>/<clinit>) first and
    # seed sibling scans with the fields they initialise, so a literal stored
    # in a constructor and consumed in another method still carries provenance.
    # If any constructor scan is incomplete, sibling scans inherit incomplete
    # (absence claims would rest on partial field knowledge).
    ctor_fields: dict[str, dict] = {}
    ctor_complete: dict[str, bool] = {}
    # One-pass indexes shared by constructor seeding and call-target lookups.
    # Rescanning the whole flow map per class / per call site is quadratic and
    # is the demonstrated large-app bottleneck (classes x flows comparisons).
    ctors_by_class: dict[str, list[MethodRef]] = {}
    flow_by_key: dict[tuple[str, str, str], list[MethodRef]] = {}
    if flows:
        ctors_by_class, flow_by_key = _index_flows(flows)
        classes = {m.class_name for m in flows}
        for cls in classes:
            summary: dict = {}
            complete_all = True
            for m in sorted(ctors_by_class.get(cls, ()), key=str):
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
                bucket = flow_by_key.get(
                    (call.invoke_class[1:-1].replace("/", "."),
                     call.invoke_method, want_desc))
                # First match in flow-map iteration order, exactly as the
                # previous linear next() scan (ambiguous keys keep first-match
                # semantics here; the unique-match rule lives in
                # _resolve_callee and is untouched).
                callee = bucket[0] if bucket else None
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
        # Derived-key route: literal -> pure return-transform -> sink call.
        # A call argument whose only provenance is ("res", invoke-id) (an
        # unmodelled call return) is re-examined: when the producing invoke is
        # an exactly-resolved static/direct call to a closed-world pure
        # transform (see _derived_transform_literal), that return MAY depend
        # on the literal's content under bounded static over-approximation -
        # the transformed bytes are NOT modelled and no decoded key value,
        # length or validity is ever claimed. The
        # derived material may seed ONE more exact static/direct hop into a
        # sink method - cross-class allowed for this route only - and
        # key-material evidence found there is reported as
        # "key-material-argument-derived". Only evidence for the derived
        # literal is collected from this scan: direct cross-class literal
        # routes stay unauthorized. Every check fails closed; incomplete or
        # field-dependent scans feed the same uncertainty bookkeeping as the
        # direct chaining above.
        # The derived tier is ACTIVE only on a verified-complete DEX ledger:
        # first-wins duplicate classes or ambiguity could hide a second
        # definition behind the resolved callee. dex_complete None (metadata
        # absent) means UNKNOWN and fails closed exactly like False. The
        # direct tier above never consults this flag.
        if (scan is not None and method.name not in ("<init>", "<clinit>")
                and dex_complete is True):
            calls_by_id = {c.invoke_id: c for c in scan.calls if c.invoke_id}
            for call in scan.calls:
                if (call.invoke_descriptor is None
                        or call.opcode not in ("invoke-static", "invoke-direct")):
                    continue
                derived: dict[int, tuple[str, CallRecord]] = {}
                for pos, origins in enumerate(call.arg_origins):
                    # Branch-union mixing guard: the position must carry
                    # EXACTLY one origin and it must be a call result. A
                    # union with external, field, literal or another result
                    # suppresses the position entirely.
                    if len(origins) != 1:
                        continue
                    origin = next(iter(origins))
                    if not origin or origin[0] != "res":
                        continue
                    producer = calls_by_id.get(origin[1])
                    if producer is None or producer is call:
                        continue
                    value = _derived_transform_literal(producer, flows, frame_info,
                                                       flow_index=flow_by_key)
                    if value is not None:
                        derived[pos] = (value, producer)
                if not derived:
                    continue
                callee = _resolve_callee(flows, call.invoke_class, call.invoke_method,
                                         call.invoke_descriptor, flow_index=flow_by_key)
                if callee is None or callee == method or callee not in (frame_info or {}):
                    continue
                widths = _param_slots(call.invoke_descriptor)
                if widths is None:
                    continue
                registers_size, callee_static = frame_info[callee]
                if call.is_static != callee_static:
                    continue
                params = parameter_registers(call.invoke_descriptor, registers_size,
                                             callee_static)
                if not params or len(params) != len(widths):
                    continue
                words = call.arg_origins
                this_words = 0 if call.is_static else 1
                if len(words) != this_words + sum(widths):
                    continue
                derived_words = {pos - this_words: dv for pos, dv in derived.items()
                                 if pos >= this_words}
                if not derived_words:
                    continue
                entry_state: dict[int, frozenset] = {}
                if this_words:
                    entry_state[params[0] - 1 if params[0] > 0 else 0] = words[0]
                    words = words[1:]
                cursor = 0
                for reg, width in zip(params, widths):
                    if cursor in derived_words:
                        entry_state[reg] = frozenset({("keybytes", derived_words[cursor][0])})
                    else:
                        entry_state[reg] = words[cursor]
                    cursor += width
                callee_scan = scan_method_flow(flows[callee], entry_state=entry_state,
                                               entry_fields=ctor_fields.get(callee.class_name) or None)
                if not callee_scan.complete or not scan.complete:
                    deferred_incomplete.add((method.class_name, callee.name))
                    incomplete_callers.add(method)
                if callee_scan.field_dependent or scan.field_dependent:
                    for value in callee_scan.evidence:
                        deferred_fielddep.add((method.class_name, value))
                derived_values = {dv[0] for dv in derived_words.values()}
                producers = {dv[0]: dv[1] for dv in derived_words.values()}
                for value, evs in callee_scan.evidence.items():
                    if value not in derived_values:
                        continue  # only the derived literal's evidence is in scope
                    producer = producers[value]
                    prefixed = [
                        FlowEvidence(
                            "key-material-argument-derived"
                            if e.kind == "key-material-argument" else e.kind,
                            f"[via internal call {callee.name} at offset {call.offset} "
                            f"in {method.class_name}.{method.name}] [derived: literal is an "
                            f"argument of the closed-world pure transform "
                            f"{producer.invoke_class}->{producer.invoke_method} at offset "
                            f"{producer.offset} (no field reads, no external sources, single "
                            f"return); bounded static over-approximation shows the "
                            f"transform's return MAY depend on the literal's content and "
                            f"reaches this sink. Transform output bytes are not modelled: "
                            f"no assertion that the output is valid decoded key bytes, "
                            f"its length, or its exact value] {e.detail}")
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
        "not_placeholder": not _is_placeholder(candidate.value),
    }
    derived_only = (
        any(e.kind == "key-material-argument-derived" for e in candidate.evidence)
        and not any(e.kind == "key-material-argument" for e in candidate.evidence)
    )
    if derived_only:
        # Derived-route evidence MAY-depend provenance only: the transform's
        # output bytes are unmodelled, so the literal's own string shape can
        # never upgrade the candidate. Leave the clause UNESTABLISHED whatever
        # format_and_entropy_ok says - the gate cannot pass on shape.
        attributes["format_assessment"] = (
            "credential format/entropy assessment inapplicable: derived-route "
            "key material (transform output bytes unmodelled; literal shape "
            f"establishes nothing about the value at the sink) ({reason})"
        )
    elif ok or candidate.used_in_security_context is not True:
        attributes["format_and_entropy_ok"] = ok
        attributes["format_and_entropy_basis"] = reason
    else:
        # The credential-shape predicate is inapplicable to role-proven key
        # material (encoded keys are arbitrary bytes; shape/entropy say
        # nothing about key role or safety). Leave the clause UNESTABLISHED -
        # absent reads as missing evidence in the gate, never as a decisive
        # refutation - and attach the explanation for review.
        attributes["format_assessment"] = (
            "credential format/entropy assessment inapplicable: key-material "
            f"role established by flow evidence ({reason})"
        )
    if candidate.used_in_security_context is True:
        attributes["used_in_security_context"] = True
        # Per-evidence uncertainty for downstream presentation: a blanket True
        # must not hide what the claim rests on. Direct key-material evidence
        # stands on its own; derived-only evidence is a may-depend route with
        # unmodelled output bytes.
        attributes["security_use_basis"] = (
            "direct-key-material-evidence"
            if any(e.kind == "key-material-argument" for e in candidate.evidence)
            else "may-depend-derived-route-only"
        )
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
