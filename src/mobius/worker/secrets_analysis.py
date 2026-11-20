"""Container entrypoint: bounded hardcoded-secret CANDIDATE scan of one staged APK.

Runs the deterministic detector (core.secrets) over /work/input.apk inside a
networkless OCI container and emits the phase-1 secrets-analysis payload on
stdout. The API validates the payload with
``mobius.adapters.secrets_payload.validate_secrets_analysis_payload`` before
anything it claims touches a finding.

Candidate-only contract, worker side:

* The worker transports FACTS ONLY: a redacted structural candidate identity
  (class, method, descriptor, const-string instruction offset), enumerated
  evidence kinds with integer offsets and strictly-shaped references, flow
  completeness and a placeholder screening outcome. The literal value never
  leaves the container: not in the payload, not in logs, not in error
  messages (failures print the exception TYPE only, never its message).
* No verdicts, no gate attributes, no prose. Attributes are derived
  server-side; CONFIRMED and REJECTED stay unreachable in phase 1.
* Evidence arrives from the detector as (kind, machine-generated detail).
  The detail is parsed with strict anchored templates copied from the
  detector's format strings; anything that does not match exactly is NOT
  repaired or guessed - the whole candidate is counted conversion_failed,
  never disguised as a clean evidence_less result. Template drift is
  therefore loud in tests and fail-closed in production, never silently
  trusted.
* Deterministic mapping: candidate identity uses the LOWEST const-string
  instruction offset at which the literal occurs in the method; candidates
  are sorted by identity before the transport cap is applied; evidence
  items are sorted canonically. Identical input bytes give identical
  output bytes.
* Accounting: screened_total counts every detector-admitted candidate;
  evidence_less counts candidates the detector admitted WITHOUT evidence;
  conversion_failed counts candidates whose detector evidence could not be
  transported INTACT (any unparseable or unresolvable item discards the
  candidate's whole evidence set) - a mapping failure, never disguised as
  a clean no-evidence result; merged counts candidates collapsed onto a
  shared const-string identity; transported candidates are the rest, up
  to the schema cap; truncated is set when the cap drops candidates.

Exit codes are failure classes, never decorations: 2 = staged-input contract
violation, 3 = analysis failure, 4 = output budget exceeded.
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import re
import sys
import zipfile
from pathlib import Path
from typing import Mapping, Sequence

from ..adapters.android_manifest import parse_apk
from ..adapters.flow_adapt import DexBlobCoverage, adapt_code
from ..adapters.provider_payload import dex_ledger_complete
from ..adapters.secrets_payload import (
    MAX_CANDIDATES,
    MAX_SECRETS_JSON_BYTES,
    validate_secrets_analysis_payload,
)
from ..core.flow import FlowBlock, SInstruction
from ..core.reachability import MethodRef
from ..core.secrets import (
    SecretCandidate,
    _is_placeholder,
    detect_hardcoded_secrets,
)


class MethodsBoundExceeded(Exception):
    """Adapted method count exceeded the service's explicit method bound.

    Raised before any detection work: an over-bounds input is an explicit
    service limit (same 50,000 bound the provider worker refuses at and the
    payload schema enforces), never a detector verdict and never a malformed
    payload. Carries the structural count only - never app data.
    """

    def __init__(self, methods: int) -> None:
        super().__init__()
        self.methods = methods

#: The only path this binary may read; the OCI contract stages exactly one file.
_STAGED_INPUT = Path("/work/input.apk")

#: Strict anchored copies of the detector's machine-generated evidence detail
#: templates (core.flow / core.secrets). Class references inside the base
#: detail are DESCRIPTOR form (Ljava/security/KeyStore;); prefix classes are
#: dotted. Anything outside these shapes is not evidence this worker can
#: transport.
_VIA_PREFIX = re.compile(
    r"\[via internal call (?P<callee>[^\s\[\]]+) at offset (?P<call_offset>\d+)"
    r" in (?P<cls>[^\s\[\]]+)\.(?P<mname>[^\s\[\].]+)\] ")
_IN_PREFIX = re.compile(
    r"\[in (?P<cls>[^\s\[\]]+)\.(?P<mname>[^\s\[\].]+)\] ")
_DERIVED_PREFIX = re.compile(
    r"\[derived: literal is an argument of the closed-world pure transform "
    r"(?P<tclass>\S+)->(?P<tmethod>\S+) at offset (?P<toffset>\d+) "
    r"\(no field reads, no external sources, single return\); bounded static "
    r"over-approximation shows the transform's return MAY depend on the "
    r"literal's content and reaches this sink\. Transform output bytes are "
    r"not modelled: no assertion that the output is valid decoded key bytes, "
    r"its length, or its exact value\] ")
_KEY_MATERIAL_BASE = re.compile(
    r"const-string literal flows via byte/char conversion into the "
    r"key/password argument \(register position (?P<pos>\d+)\) of "
    r"(?P<sclass>\S+)->(?P<smethod>\S+) at offset (?P<soffset>\d+)")
_COMPARISON_BASE = re.compile(
    r"const-string literal compared by (?P<sclass>\S+)->(?P<smethod>\S+)"
    r" against external input \(.*\); result consumed by \S+ at offset "
    r"(?P<soffset>\d+)\. Comparison\+branch shape is shared with UI "
    r"routing/dispatch; review-only\.")

_DESCRIPTOR_CLASS = re.compile(r"L[A-Za-z0-9_$/]+;")


def _compact(descriptor: str) -> str:
    """DEX-canonical descriptor form. androguard renders method-key
    descriptors with spaces between parameter types ("([B [B)[B") while
    invoke references are compact; DEX descriptors never contain spaces, so
    stripping them is normalization, not interpretation. The schema's
    descriptor shape forbids spaces, so the worker emits compact form
    everywhere."""
    return descriptor.replace(" ", "")


class WorkerError(Exception):
    """A worker-internal contradiction; the run fails, nothing is guessed."""


class _StringsIndex:
    """Minimal CodeIndex stand-in: literal tuples per method, exactly what
    detect_hardcoded_secrets reads."""

    def __init__(self, strings: Mapping[MethodRef, tuple[str, ...]]):
        self.strings = strings


def _dotted(descriptor_class: str) -> str | None:
    """Descriptor-form class (Lcom/foo/Bar;) to dotted, or None when the
    shape is not a plain class descriptor."""
    if not _DESCRIPTOR_CLASS.fullmatch(descriptor_class):
        return None
    return descriptor_class[1:-1].replace("/", ".")


def _method_by_name(
    flows: Mapping[MethodRef, Sequence[FlowBlock]], class_name: str, name: str
) -> MethodRef | None:
    """The unique method with this class/name, else None (overloaded or
    absent: the worker cannot know which, so it refuses to guess)."""
    matches = [ref for ref in flows
               if ref.class_name == class_name and ref.name == name]
    return matches[0] if len(matches) == 1 else None


def _instruction_at(
    flows: Mapping[MethodRef, Sequence[FlowBlock]],
    ref: MethodRef, offset: int,
) -> SInstruction | None:
    """The single instruction at this offset in the method, if any."""
    for block in flows.get(ref, ()):
        for ins in block.instructions:
            if ins.offset == offset:
                return ins
    return None


def _invoke_descriptor_at(
    flows: Mapping[MethodRef, Sequence[FlowBlock]],
    ref: MethodRef, offset: int, invoke_class: str, invoke_method: str,
) -> str | None:
    """Descriptor of the invoke at exactly this offset, verified against the
    claimed target. Offset identifies one instruction within a method."""
    for block in flows.get(ref, ()):
        for ins in block.instructions:
            if ins.offset == offset:
                if ins.invoke_class == invoke_class and ins.invoke_method == invoke_method:
                    return ins.invoke_descriptor
                return None
    return None


def _unique_invoke_descriptor(
    flows: Mapping[MethodRef, Sequence[FlowBlock]],
    ref: MethodRef, invoke_class: str, invoke_method: str,
) -> str | None:
    """Comparison evidence names the branch offset, not the invoke; the
    descriptor is recoverable only when exactly one matching invoke exists
    in the containing method."""
    found = {
        ins.invoke_descriptor
        for block in flows.get(ref, ())
        for ins in block.instructions
        if ins.invoke_class == invoke_class and ins.invoke_method == invoke_method
    }
    found.discard(None)
    return found.pop() if len(found) == 1 else None


def _parse_evidence(
    kind: str, detail: str,
    flows: Mapping[MethodRef, Sequence[FlowBlock]],
    declaring: MethodRef,
) -> dict | None:
    """One detector evidence item to its schema shape, or None when any part
    fails to parse or resolve. Never repairs, never guesses."""
    rest = detail
    container: MethodRef | None = declaring
    derived = None
    match = _VIA_PREFIX.match(rest)
    if match:
        rest = rest[match.end():]
        # The chained callee is resolved through the call instruction at the
        # stated call offset in the declaring method: exact class, method and
        # descriptor, never a name lookup. The derived route allows a
        # cross-class sink hop, so the prefix's bare callee name is only a
        # consistency check. The prefix's own class/method must name the
        # declaring method.
        if (match.group("cls"), match.group("mname")) != (declaring.class_name,
                                                          declaring.name):
            # Bounded fallback re-anchor: the detector attached the candidate
            # to a fallback method (e.g. <clinit>) while the prefix names the
            # method that actually carried the evidence. Re-anchor ONLY when
            # the prefix names a method in the SAME class whose name is
            # UNIQUE there. Every later check still runs exactly against the
            # re-anchored method: the call instruction at the exact call
            # offset with exact target class/method/descriptor, and unique
            # callee resolution. Anything wider stays conversion_failed -
            # a visible gap, never a loosened match.
            if match.group("cls") != declaring.class_name:
                return None
            declaring = _method_by_name(flows, match.group("cls"),
                                        match.group("mname"))
            if declaring is None:
                return None
        call = _instruction_at(flows, declaring, int(match.group("call_offset")))
        if (call is None or call.invoke_method != match.group("callee")
                or call.invoke_class is None or call.invoke_descriptor is None):
            return None
        callee_class = _dotted(call.invoke_class)
        if callee_class is None:
            return None
        wanted = _compact(call.invoke_descriptor)
        matches = [ref for ref in flows
                   if ref.class_name == callee_class
                   and ref.name == call.invoke_method
                   and _compact(ref.descriptor) == wanted]
        if len(matches) != 1:
            return None
        container = matches[0]
        derived_match = _DERIVED_PREFIX.match(rest)
        if derived_match:
            rest = rest[derived_match.end():]
            derived = derived_match.groupdict()
    else:
        match = _IN_PREFIX.match(rest)
        if match:
            rest = rest[match.end():]
            container = _method_by_name(flows, match.group("cls"), match.group("mname"))
    if container is None:
        return None

    if kind in ("key-material-argument", "key-material-argument-derived"):
        base = _KEY_MATERIAL_BASE.fullmatch(rest)
        if base is None:
            return None
        if (kind == "key-material-argument-derived") != (derived is not None):
            return None  # kind/structure disagreement: not transportable
        sink_class = _dotted(base.group("sclass"))
        if sink_class is None:
            return None
        sink_descriptor = _invoke_descriptor_at(
            flows, container, int(base.group("soffset")),
            base.group("sclass"), base.group("smethod"))
        if sink_descriptor is None:
            return None
        item = {
            "kind": kind,
            "container_class": container.class_name,
            "container_method": container.name,
            "container_descriptor": _compact(container.descriptor),
            "sink_class": sink_class,
            "sink_method": base.group("smethod"),
            "sink_descriptor": _compact(sink_descriptor),
            "sink_offset": int(base.group("soffset")),
            "arg_position": int(base.group("pos")),
        }
        if derived is not None:
            transform_descriptor = _invoke_descriptor_at(
                flows, declaring, int(derived["toffset"]),
                derived["tclass"], derived["tmethod"])
            transform_class = _dotted(derived["tclass"])
            if transform_descriptor is None or transform_class is None:
                return None
            item.update({
                "transform_class": transform_class,
                "transform_method": derived["tmethod"],
                "transform_descriptor": _compact(transform_descriptor),
                "transform_offset": int(derived["toffset"]),
            })
        return item

    if kind == "access-comparison-suspect":
        if derived is not None:
            return None  # the detector never derives comparison evidence
        base = _COMPARISON_BASE.fullmatch(rest)
        if base is None:
            return None
        sink_class = _dotted(base.group("sclass"))
        if sink_class is None:
            return None
        sink_descriptor = _unique_invoke_descriptor(
            flows, container, base.group("sclass"), base.group("smethod"))
        if sink_descriptor is None:
            return None
        return {
            "kind": kind,
            "container_class": container.class_name,
            "container_method": container.name,
            "container_descriptor": _compact(container.descriptor),
            "sink_class": sink_class,
            "sink_method": base.group("smethod"),
            "sink_descriptor": _compact(sink_descriptor),
            "sink_offset": int(base.group("soffset")),
        }
    return None  # unknown kind: not transportable


def _identity_occurrence(
    flows: Mapping[MethodRef, Sequence[FlowBlock]],
    ref: MethodRef, literal: str,
) -> tuple[MethodRef, int]:
    """The canonical const-string instruction carrying this literal: the
    first occurrence in (method-string, offset) order across the declaring
    CLASS. The wire identity locates the literal's instruction, not the
    detector's attachment method: constructor-merged and flow-evidenced
    fallback candidates can be attached to a method (e.g. <clinit>) that
    never declares the literal, and an offset borrowed from an unnamed
    sibling collides between distinct literals. No occurrence anywhere in
    the class is a worker-internal contradiction: the detector keyed the
    candidate on this literal."""
    # A literal occurring in the attachment method identifies the candidate
    # by (attachment method, lowest local offset) - so the same literal
    # admitted under several methods stays distinct, per the detector's
    # (method, value) keying.
    local = [
        ins.offset
        for block in flows.get(ref, ())
        for ins in block.instructions
        if ins.literal == literal
    ]
    if local:
        return ref, min(local)
    # Constructor-merged and flow-evidenced fallback candidates can be
    # attached to a method (e.g. <clinit>) that never declares the literal:
    # locate the canonical const-string instruction in the declaring CLASS
    # (first in (method-string, offset) order) and name it, because an
    # unnamed sibling's offset collides between distinct literals.
    occurrences = sorted(
        (str(mref), ins.offset, mref)
        for mref, blocks in flows.items()
        if mref.class_name == ref.class_name
        for block in blocks
        for ins in block.instructions
        if ins.literal == literal
    )
    if not occurrences:
        raise WorkerError("admitted candidate has no literal occurrence in its class")
    _, offset, method = min(occurrences, key=lambda item: (item[0], item[1]))
    return method, offset


def build_secrets_payload(
    *,
    artifact_sha256: str,
    package_name: str,
    flows: Mapping[MethodRef, Sequence[FlowBlock]],
    ledger: Sequence[DexBlobCoverage],
    candidates: Sequence[SecretCandidate],
) -> dict:
    """Detector output to the phase-1 wire payload. Pure and deterministic."""
    screened_total = len(candidates)
    rows: dict[tuple, dict] = {}
    evidence_less = 0
    conversion_failed = 0
    for candidate in candidates:
        if not candidate.evidence:
            evidence_less += 1  # detector admitted it WITHOUT evidence
            continue
        evidence = [
            _parse_evidence(e.kind, e.detail, flows, candidate.method)
            for e in candidate.evidence
        ]
        if any(item is None for item in evidence):
            # The detector DID supply evidence; a mapping failure is never
            # disguised as a clean no-evidence result.
            conversion_failed += 1
            continue
        method, offset = _identity_occurrence(flows, candidate.method,
                                              candidate.literal)
        identity = (method.class_name, method.name, _compact(method.descriptor),
                    offset)
        item_keys = {
            "evidence": [
                item for item in evidence],
        }
        if identity in rows:
            # Same literal admitted under a second attachment method: one
            # secret, one const-string instruction, one wire candidate.
            # Merge explicitly: union evidence (each item parsed against its
            # own attachment context), AND flow completeness. Counted in the
            # "merged" accounting category, never silently dropped.
            existing = rows[identity]
            seen_items = {json.dumps(item, sort_keys=True)
                          for item in existing["evidence"]}
            for item in evidence:
                key = json.dumps(item, sort_keys=True)
                if key not in seen_items:
                    seen_items.add(key)
                    existing["evidence"].append(item)
            existing["flow_complete"] = (existing["flow_complete"]
                                         and candidate.flow_complete)
            existing["_merged"] += 1
            continue
        rows[identity] = {
            "method_class": method.class_name,
            "method_name": method.name,
            "method_descriptor": _compact(method.descriptor),
            "literal_offset": offset,
            "placeholder_screening": (
                "placeholder" if _is_placeholder(candidate.value)
                else "not-placeholder"),
            "flow_complete": candidate.flow_complete,
            "evidence": item_keys["evidence"],
            "_merged": 0,
        }
    merged = sum(row["_merged"] for row in rows.values())
    for row in rows.values():
        del row["_merged"]
        row["evidence"] = sorted(
            row["evidence"],
            key=lambda item: (
                item["kind"], item["sink_class"], item["sink_method"],
                item["sink_offset"], item.get("arg_position", -1),
                item.get("transform_offset", -1)))
    transportable = sorted(rows.values(),
        key=lambda row: (row["method_class"], row["method_name"],
                         row["method_descriptor"], row["literal_offset"]))
    truncated = len(transportable) > MAX_CANDIDATES
    transported = transportable[:MAX_CANDIDATES]
    return {
        "schema_version": 1,
        "artifact_sha256": artifact_sha256,
        "package_name": package_name,
        "methods_adapted": len(flows),
        "truncated": truncated,
        "counts": {
            "screened_total": screened_total,
            "evidence_less": evidence_less,
            "conversion_failed": conversion_failed,
            "merged": merged,
        },
        "dex_coverage": [
            {
                "entry": blob.entry,
                "status": blob.status,
                "size_bytes": blob.size_bytes,
                "methods": blob.methods,
                "duplicates": blob.duplicates,
                "ambiguous": blob.ambiguous,
            }
            for blob in ledger
        ],
        "candidates": transported,
    }


def _static_flags(apk: bytes, flows: Mapping[MethodRef, Sequence[FlowBlock]]):
    """Access flags per method, first-dex-wins over classes*.dex entries.
    Entries the ledger already recorded as unparseable are skipped here; the
    ledger carries that gap."""
    from androguard.core.dex import DEX

    flags: dict[MethodRef, bool] = {}
    with zipfile.ZipFile(io.BytesIO(apk)) as archive:
        for name in sorted(
                n for n in archive.namelist()
                if re.fullmatch(r"classes\d*\.dex", n)):
            try:
                vm = DEX(archive.read(name))
            except Exception:
                continue
            for cls in vm.get_classes():
                dotted = cls.get_name()[1:-1].replace("/", ".")
                for em in cls.get_methods():
                    ref = MethodRef(dotted, em.get_name(), em.get_descriptor())
                    if ref not in flags:
                        flags[ref] = "static" in em.get_access_flags_string()
    return {ref: flags.get(ref, False) for ref in flows}


def run(apk: bytes) -> dict:
    """Full pipeline: APK bytes to validated wire payload."""
    digest = hashlib.sha256(apk).hexdigest()
    surface = parse_apk(apk)
    flows, registers_sizes, superclasses, try_regions, ledger, _origins = adapt_code(apk)
    # Truthful bounds reporting, mirroring the provider worker: refuse an
    # over-bounds APK explicitly and BEFORE spending detection time on it,
    # so it can never die late as a schema-validation failure that reads as
    # a malformed payload. 50,000 is the service's method bound, mirrored by
    # the payload schema's methods_adapted le=50000.
    if len(flows) > 50000:
        raise MethodsBoundExceeded(len(flows))
    static = _static_flags(apk, flows)
    frame_info = {
        ref: (registers_sizes.get(ref, 0), static.get(ref, False)) for ref in flows
    }
    strings = {}
    for ref, blocks in flows.items():
        literals = tuple(sorted(
            {ins.literal for b in blocks for ins in b.instructions if ins.literal}
        ))
        if literals:
            strings[ref] = literals
    candidates = detect_hardcoded_secrets(
        _StringsIndex(strings), flows, frame_info,
        dex_complete=dex_ledger_complete(ledger))
    payload = build_secrets_payload(
        artifact_sha256=digest,
        package_name=surface.package_name,
        flows=flows,
        ledger=ledger,
        candidates=candidates,
    )
    # The worker validates its own output against the API contract before
    # emitting it; a payload the API would reject never leaves the container.
    validate_secrets_analysis_payload(json.dumps(payload).encode(), digest)
    return payload


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True)
    args = parser.parse_args()
    source = Path(args.input)
    if source != _STAGED_INPUT or not source.is_file() or source.is_symlink():
        print("input must be the staged /work/input.apk regular file", file=sys.stderr)
        return 2
    try:
        payload = run(source.read_bytes())
        encoded = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    except MethodsBoundExceeded as exc:
        # Explicit service limit, labelled as such (provider-worker pattern);
        # the count is structural accounting, never app data.
        print(
            f"secrets analysis input exceeds the service method bound "
            f"({exc.methods} adapted methods > 50000); the APK is too large "
            "for this service's explicit limits",
            file=sys.stderr,
        )
        return 4
    except Exception as exc:
        # Type name only: an exception message could embed app data.
        print(f"secrets analysis failed: {type(exc).__name__}", file=sys.stderr)
        return 3
    if len(encoded) > MAX_SECRETS_JSON_BYTES:
        print("secrets analysis JSON exceeds the output budget", file=sys.stderr)
        return 4
    sys.stdout.buffer.write(encoded)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
