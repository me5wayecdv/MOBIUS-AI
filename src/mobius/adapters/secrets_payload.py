"""Versioned, bounded wire format for hardcoded-secret CANDIDATES from isolated workers.

The worker runs the secrets detector (core.secrets) over the staged APK inside a
networkless OCI container and emits this payload. The API validates it here
before anything it claims touches a finding.

Phase-1 contract: candidate-only. CONFIRMED and REJECTED are UNREACHABLE,
enforced here in the source-owned attribute derivation - not measured on a
corpus:

* The worker transports FACTS ONLY: a redacted structural candidate identity
  (class, method, descriptor, const-string instruction offset), enumerated
  evidence kinds with integer offsets and strictly-shaped descriptors, flow
  completeness and a placeholder screening outcome. No literal value, no
  literal hash (a full hash of a short secret is brute-forceable; a short one
  collides), no gate attributes, no verdicts, no prose. Explanation text is
  rendered API-side from templates; worker prose is never stored.
* ``format_and_entropy_ok`` is NEVER written for any candidate in phase 1 -
  including direct-tier rows - because the redacted payload cannot support
  recomputing it and a worker claim about it is unverifiable. The clause is
  missing (not False), so the gate cannot pass and no decisive failure maps
  to an inaccurate rejection reason. Raising this cap later is a separate
  reviewed decision.
* A placeholder-screened candidate is DROPPED (counted and recorded as
  dropped), never written with ``not_placeholder: false``: a decisive False
  clause would map to REJECTED via a fallback reason that does not fit.
* Placeholder screening is worker-asserted: the API cannot recompute it
  without the literal. It is recorded as worker-asserted, never as truth.
* DEX completeness is recomputed API-side from the carried ledger
  (``dex_ledger_complete``), which validates internal CONSISTENCY only; the
  ledger is worker-supplied, so completeness remains WORKER-ASSERTED unless
  the apply route independently checks it against source bytes. The ledger
  state is recorded on every candidate.
* ``security_use_basis`` annotations from the detector do not survive
  ``as_gate_evidence``; the direct vs MAY-depend distinction is therefore
  retained deliberately in the source-owned title/description/evidence
  rendering here. Nothing worker-annotated is trusted for it; it is derived
  from the enumerated evidence kinds alone.

Boundary of what validation proves:

* Candidate and evidence references are checked for SHAPE, uniqueness and
  membership in the detector's enumerated sink vocabulary only. Method
  EXISTENCE in the DEX is not verified here and must not be claimed from
  aggregate ledger counts; the apply step may verify references where its
  source data permits. Package consistency and the sha-256 anchor against
  the submission are checked at apply, as the provider path does.
* Evidence lines are rendered as WORKER-REPORTED: the API validated their
  structure, not their truth. Placeholder screening and DEX completeness
  are worker-asserted for the same reason and labelled as such.
* The DEX ledger carries no worker prose: entry names are constrained to
  real ``classes*.dex`` shapes and the outcome lives in the enumerated
  status alone (no error string exists in this schema).
* Strict identifier shapes are an explicit availability limit: dotless
  default-package classes and non-ASCII identifiers (common under
  obfuscation) fail validation, and because validation rejects the whole
  payload rather than silently dropping candidates, such an app yields no
  result at all. That fails closed; widening the shapes needs its own
  tests.
* Contradictory payloads (derived evidence on a ledger recomputed as
  incomplete) reject the WHOLE payload, direct candidates included: a
  worker that contradicts the detector contract is not trusted for the
  rest. This is why no "derived evidence inadmissible" rendering branch
  exists - the state is unreachable in an accepted payload.
* Accounting is part of the contract: ``counts.screened_total`` and
  ``counts.evidence_less`` are worker-asserted; ``transported`` is
  API-counted from the payload; placeholder drops are API-counted at
  derivation. Consistency is enforced (screened_total = transported +
  evidence_less when untruncated; >= when truncated). Evidence-less
  filtering is its own category and is never reported as truncation.
  Persistence of these counts is the apply step's job, not this module's.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from .flow_adapt import DexBlobCoverage
from .provider_payload import dex_ledger_complete

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_CLASS = re.compile(r"^[A-Za-z_$][A-Za-z0-9_$]*(\.[A-Za-z_$][A-Za-z0-9_$]*)+$")
_METHOD = re.compile(r"^([A-Za-z_$][A-Za-z0-9_$]*|<init>|<clinit>)$")
# DEX type descriptor: primitives, objects, arrays; return may be V.
_TYPE = r"(?:[ZBSCIJFD]|\[*L[A-Za-z0-9_/$]+;|\[*[ZBSCIJFD])"
_DESCRIPTOR = re.compile(r"^\(" + _TYPE + r"*\)(?:V|" + _TYPE + r")$")

# Measured facts about the size bounds, without overclaiming:
# - The worker self-caps its JSON at this size before writing a byte. That is
#   worker-asserted behavior: it holds only while the image contains this
#   exact worker code and is verified by worker-side tests, not by anything
#   on the API side.
# - The runner truncates raw container stdout at max_output_bytes (6 MiB).
#   That is a cap on raw stdout bytes, NOT a serialized-DB cap: a truncated
#   payload is rejected before storage (output_truncated check + JSON/schema
#   validation), so truncation cannot write a row.
# - The API re-validates the stored payload (including this size bound) at
#   apply time, before anything is written to the scan; apply tests prove
#   that rejection. That check gates APPLY, not STORAGE: it runs after
#   result_json was stored, so it cannot prevent an oversize row from being
#   stored, only from being applied.
# No independent storage-level cap (e.g. a DB CHECK constraint on
# result_json size) has been verified; nothing below asserts one.
MAX_SECRETS_JSON_BYTES = 4 * 1024 * 1024
MAX_CANDIDATES = 512
MAX_EVIDENCE_PER_CANDIDATE = 64
MAX_LEDGER_ENTRIES = 64
MAX_OFFSET = 1 << 24
MAX_ARG_POSITION = 64

#: Verbatim from core.secrets/flow evidence kinds; anything else is
#: schema-invalid, not "a new outcome".
_ALLOWED_EVIDENCE_KIND = {
    "key-material-argument",
    "key-material-argument-derived",
    "access-comparison-suspect",
}
_KEY_MATERIAL_KINDS = {"key-material-argument", "key-material-argument-derived"}
_ALLOWED_PLACEHOLDER_SCREEN = {"placeholder", "not-placeholder"}
_ALLOWED_LEDGER_STATUS = {"parsed", "failed-parse", "skipped-oversized",
                          "skipped-aggregate", "duplicate-entry"}
_GATE_CLAUSE_KEYS = ("located", "format_and_entropy_ok", "not_placeholder",
                     "used_in_security_context")

#: Enumerated from the detector source (core.flow _KEY_MATERIAL_ARGS), dotted
#: class form. The detector keys on (class, method) and argument position; it
#: does NOT constrain the descriptor, so neither does this schema - pinning
#: one would reject legitimate overloads the detector accepts.
_ALLOWED_KEY_SINKS: dict[tuple[str, str], frozenset[int]] = {
    ("javax.crypto.spec.SecretKeySpec", "<init>"): frozenset({1}),
    ("javax.crypto.spec.PBEKeySpec", "<init>"): frozenset({1}),
    ("java.security.KeyStore", "load"): frozenset({2}),
}
#: core.flow _COMPARISONS, dotted class form.
_ALLOWED_COMPARISON_SINKS: frozenset[tuple[str, str]] = frozenset({
    ("java.lang.String", "equals"),
    ("java.lang.String", "equalsIgnoreCase"),
    ("java.lang.String", "contentEquals"),
    ("java.lang.String", "compareTo"),
})


class _InvariantViolation(RuntimeError):
    """The phase-1 construction contract was broken internally. Raised, never
    asserted, so it holds under python -O as well."""


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class LedgerDTO(StrictModel):
    # Real classes*.dex entry names only; no path text, no worker prose.
    # The outcome lives in the enumerated status alone, so the schema
    # carries no error string at all.
    entry: str = Field(pattern=r"^classes\d*\.dex$", max_length=256)
    status: str
    size_bytes: int = Field(ge=0, le=64 * 1024 * 1024)
    methods: int = Field(default=0, ge=0, le=50000)
    duplicates: int = Field(default=0, ge=0, le=50000)
    ambiguous: bool = False


class EvidenceDTO(StrictModel):
    """One enumerated evidence fact. Offsets/positions are integers; classes,
    methods and descriptors must match strict DEX shapes. No free text."""

    kind: str
    # The method the offsets are relative to, carried explicitly so a
    # sink_offset is locatable. For comparison evidence, sink_offset is the
    # consuming BRANCH offset in this container, not the invoke offset.
    container_class: str = Field(max_length=1000)
    container_method: str = Field(max_length=200)
    container_descriptor: str = Field(max_length=2000)
    sink_class: str | None = Field(default=None, max_length=1000)
    sink_method: str | None = Field(default=None, max_length=200)
    sink_descriptor: str | None = Field(default=None, max_length=2000)
    sink_offset: int | None = Field(default=None, ge=0, le=MAX_OFFSET)
    arg_position: int | None = Field(default=None, ge=0, le=MAX_ARG_POSITION)
    transform_class: str | None = Field(default=None, max_length=1000)
    transform_method: str | None = Field(default=None, max_length=200)
    transform_descriptor: str | None = Field(default=None, max_length=2000)
    transform_offset: int | None = Field(default=None, ge=0, le=MAX_OFFSET)


class CandidateDTO(StrictModel):
    """Redacted structural identity plus enumerated facts. The identity is
    (method_class, method_name, method_descriptor, literal_offset): collision-
    safe within a scan, stable across re-runs, and leaks nothing."""

    method_class: str = Field(max_length=1000)
    method_name: str = Field(max_length=200)
    method_descriptor: str = Field(max_length=2000)
    literal_offset: int = Field(ge=0, le=MAX_OFFSET)
    placeholder_screening: str
    flow_complete: bool
    evidence: list[EvidenceDTO] = Field(default_factory=list,
                                        max_length=MAX_EVIDENCE_PER_CANDIDATE)


class CountsDTO(StrictModel):
    """Worker-reported scan accounting. Categories are nonoverlapping:
    screened_total = transported + evidence_less + conversion_failed + merged
    + truncated_away.
    evidence_less candidates were admitted by the detector WITHOUT evidence
    and deliberately not transported (the schema requires evidence); that
    filtering is its own category and is never reported as truncation.
    conversion_failed candidates DID come with detector evidence that could not
    be transported intact (template drift, unresolvable reference); counting
    them as evidence-less would disguise a conversion failure as a clean
    no-evidence result, so they are their own category and any nonzero value
    means the transport was incomplete and must never read as "scan
    complete".
    merged counts detector-admitted candidates collapsed into another wire
    candidate because they share the same const-string instruction identity
    (the detector keys candidates by (method, value); the wire keys them by
    the literal's canonical instruction). transported is API-counted;
    truncated_away exists only when the payload's truncated flag is set and
    is worker-asserted by construction."""

    screened_total: int = Field(ge=0, le=10_000_000)
    evidence_less: int = Field(ge=0, le=10_000_000)
    merged: int = Field(default=0, ge=0, le=10_000_000)
    conversion_failed: int = Field(default=0, ge=0, le=10_000_000)


class SecretsAnalysisDTO(StrictModel):
    schema_version: int = Field(ge=1, le=1)
    artifact_sha256: str
    package_name: str = Field(
        min_length=1, max_length=500,
        pattern=r"^[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z][A-Za-z0-9_]*)+$")
    methods_adapted: int = Field(ge=0, le=50000)
    truncated: bool = False
    counts: CountsDTO
    dex_coverage: list[LedgerDTO] = Field(min_length=1, max_length=MAX_LEDGER_ENTRIES)
    candidates: list[CandidateDTO] = Field(default_factory=list,
                                           max_length=MAX_CANDIDATES)


@dataclass(frozen=True, slots=True)
class SecretsEvidence:
    kind: str
    container_class: str
    container_method: str
    container_descriptor: str
    sink_class: str | None
    sink_method: str | None
    sink_descriptor: str | None
    sink_offset: int | None
    arg_position: int | None
    transform_class: str | None
    transform_method: str | None
    transform_descriptor: str | None
    transform_offset: int | None


@dataclass(frozen=True, slots=True)
class SecretsCandidateFacts:
    """Validated, redacted candidate facts. ``candidate_id`` is the structural
    identity tuple; no literal material exists anywhere in this record."""

    candidate_id: tuple[str, str, str, int]
    placeholder_screening: str  # worker-asserted
    flow_complete: bool
    evidence: tuple[SecretsEvidence, ...]

    @property
    def security_use_basis(self) -> str | None:
        """Derived from the enumerated evidence kinds alone (never from a
        worker annotation): direct evidence stands on its own; a derived-only
        route is MAY-depend evidence with unmodelled transform output."""
        kinds = {e.kind for e in self.evidence}
        if "key-material-argument" in kinds:
            return "direct-key-material-evidence"
        if "key-material-argument-derived" in kinds:
            return "may-depend-derived-route-only"
        return None


@dataclass(frozen=True, slots=True)
class SecretsAnalysisResult:
    """Validated worker output. ``dex_complete`` is recomputed API-side from
    the ledger; it attests internal consistency, not truthful parse claims."""

    package_name: str
    methods_adapted: int
    truncated: bool  # worker-asserted; surfaced, never treated as "no evidence"
    screened_total: int  # worker-asserted
    evidence_less: int  # worker-asserted, NOT transported; distinct from truncation
    merged: int  # worker-asserted; collapsed into another wire candidate
    conversion_failed: int  # worker-asserted; evidence existed but was not
    # transportable intact - transport was INCOMPLETE when nonzero
    transport_complete: bool  # API-derived: conversion_failed == 0 and not
    # truncated. Scan-level: it holds (or fails) even when ZERO candidates
    # transported, where no candidate description exists to carry the
    # marker. The apply step MUST persist scan-level incompleteness
    # regardless of candidate count.
    ledger: tuple[DexBlobCoverage, ...]
    candidates: tuple[SecretsCandidateFacts, ...]

    @property
    def dex_complete(self) -> bool:
        return dex_ledger_complete(self.ledger)


def _check_ref(class_name: str | None, method: str | None, descriptor: str | None,
               offset: int | None, label: str) -> None:
    if class_name is None or method is None or descriptor is None or offset is None:
        raise ValueError(f"secrets evidence is missing its {label} reference")
    if not _CLASS.fullmatch(class_name):
        raise ValueError(f"secrets evidence {label} class is not a DEX class name")
    if not _METHOD.fullmatch(method):
        raise ValueError(f"secrets evidence {label} method is not a DEX method name")
    if not _DESCRIPTOR.fullmatch(descriptor):
        raise ValueError(f"secrets evidence {label} descriptor is not a DEX descriptor")


def validate_secrets_analysis_payload(
    raw: bytes, expected_sha256: str
) -> SecretsAnalysisResult:
    """Validate worker output against the phase-1 contract. Raises ValueError
    on any violation; nothing invalid is partially accepted."""
    if len(raw) > MAX_SECRETS_JSON_BYTES:
        raise ValueError("secrets analysis worker output exceeds the API size limit")
    try:
        decoded = json.loads(raw)
        dto = SecretsAnalysisDTO.model_validate(decoded)
    except (UnicodeDecodeError, ValueError, ValidationError) as exc:
        raise ValueError("secrets analysis worker returned an invalid schema payload") from exc
    if not _SHA256.fullmatch(dto.artifact_sha256) or dto.artifact_sha256 != expected_sha256:
        raise ValueError("secrets analysis result is not bound to the authorized APK SHA-256")

    ledger: list[DexBlobCoverage] = []
    for item in dto.dex_coverage:
        if item.status not in _ALLOWED_LEDGER_STATUS:
            raise ValueError("secrets analysis payload has an unknown DEX coverage status")
        ledger.append(DexBlobCoverage(
            entry=item.entry, status=item.status, size_bytes=item.size_bytes,
            methods=item.methods, duplicates=item.duplicates,
            ambiguous=item.ambiguous,
        ))
    counted = [b.entry for b in ledger if b.status != "duplicate-entry"]
    if len(set(counted)) != len(counted):
        raise ValueError("duplicate DEX coverage entry in secrets analysis payload")
    if any(b.status == "duplicate-entry" and b.entry not in counted for b in ledger):
        raise ValueError("duplicate-entry ledger row without a counted original")
    if sum(b.methods for b in ledger if b.status == "parsed") != dto.methods_adapted:
        raise ValueError("secrets analysis methods-adapted count contradicts the DEX ledger")

    candidates: list[SecretsCandidateFacts] = []
    seen_ids: set[tuple[str, str, str, int]] = set()
    for c in dto.candidates:
        cid = (c.method_class, c.method_name, c.method_descriptor, c.literal_offset)
        if not _CLASS.fullmatch(c.method_class):
            raise ValueError("candidate method class is not a DEX class name")
        if not _METHOD.fullmatch(c.method_name):
            raise ValueError("candidate method name is not a DEX method name")
        if not _DESCRIPTOR.fullmatch(c.method_descriptor):
            raise ValueError("candidate method descriptor is not a DEX descriptor")
        if cid in seen_ids:
            raise ValueError("duplicate candidate identity in secrets analysis payload")
        seen_ids.add(cid)
        if c.placeholder_screening not in _ALLOWED_PLACEHOLDER_SCREEN:
            raise ValueError("unknown placeholder screening outcome in worker payload")
        if not c.evidence:
            raise ValueError("candidate without evidence facts in worker payload")
        evidence: list[SecretsEvidence] = []
        for e in c.evidence:
            if e.kind not in _ALLOWED_EVIDENCE_KIND:
                raise ValueError("unknown evidence kind in secrets analysis payload")
            if not _CLASS.fullmatch(e.container_class):
                raise ValueError("secrets evidence container class is not a DEX class name")
            if not _METHOD.fullmatch(e.container_method):
                raise ValueError("secrets evidence container method is not a DEX method name")
            if not _DESCRIPTOR.fullmatch(e.container_descriptor):
                raise ValueError("secrets evidence container descriptor is not a DEX descriptor")
            if e.kind in _KEY_MATERIAL_KINDS:
                _check_ref(e.sink_class, e.sink_method, e.sink_descriptor,
                           e.sink_offset, "sink")
                if e.arg_position is None:
                    raise ValueError("key-material evidence is missing its argument position")
                allowed = _ALLOWED_KEY_SINKS.get((e.sink_class, e.sink_method))
                if allowed is None or e.arg_position not in allowed:
                    raise ValueError(
                        "key-material evidence names a sink the detector cannot produce")
            else:
                # access-comparison-suspect: same structural checks, enumerated
                # comparison sinks; no arbitrary strings anywhere.
                _check_ref(e.sink_class, e.sink_method, e.sink_descriptor,
                           e.sink_offset, "sink")
                if (e.sink_class, e.sink_method) not in _ALLOWED_COMPARISON_SINKS:
                    raise ValueError(
                        "comparison evidence names a sink the detector cannot produce")
            if e.kind == "key-material-argument-derived":
                _check_ref(e.transform_class, e.transform_method,
                           e.transform_descriptor, e.transform_offset, "transform")
            elif (e.transform_class is not None or e.transform_method is not None
                  or e.transform_descriptor is not None or e.transform_offset is not None):
                raise ValueError("non-derived evidence carries a transform reference")
            evidence.append(SecretsEvidence(
                kind=e.kind,
                container_class=e.container_class,
                container_method=e.container_method,
                container_descriptor=e.container_descriptor,
                sink_class=e.sink_class, sink_method=e.sink_method,
                sink_descriptor=e.sink_descriptor, sink_offset=e.sink_offset,
                arg_position=e.arg_position,
                transform_class=e.transform_class, transform_method=e.transform_method,
                transform_descriptor=e.transform_descriptor,
                transform_offset=e.transform_offset,
            ))
        candidates.append(SecretsCandidateFacts(
            candidate_id=cid,
            placeholder_screening=c.placeholder_screening,
            flow_complete=c.flow_complete,
            evidence=tuple(evidence),
        ))

    # Cross-field consistency with the detector contract: the derived tier is
    # only defined on a complete, unambiguous DEX scan. Derived evidence on a
    # ledger the API recomputes as incomplete is a contradictory payload.
    if not dex_ledger_complete(ledger) and any(
            e.kind == "key-material-argument-derived"
            for c in candidates for e in c.evidence):
        raise ValueError(
            "derived-route evidence contradicts an incomplete or ambiguous DEX ledger")

    transported = len(candidates)
    accounted = (transported + dto.counts.evidence_less
                 + dto.counts.conversion_failed + dto.counts.merged)
    if dto.truncated:
        if dto.counts.screened_total < accounted:
            raise ValueError("secrets analysis counts are inconsistent with the payload")
    elif dto.counts.screened_total != accounted:
        raise ValueError("secrets analysis counts are inconsistent with the payload")

    return SecretsAnalysisResult(
        package_name=dto.package_name,
        methods_adapted=dto.methods_adapted,
        truncated=dto.truncated,
        screened_total=dto.counts.screened_total,
        evidence_less=dto.counts.evidence_less,
        merged=dto.counts.merged,
        conversion_failed=dto.counts.conversion_failed,
        transport_complete=(dto.counts.conversion_failed == 0
                            and not dto.truncated),
        ledger=tuple(ledger),
        candidates=tuple(candidates),
    )


@dataclass(frozen=True, slots=True)
class DerivedCandidate:
    """Source-owned per-candidate output: gate attributes, rendering text and
    the drop decision. ``dropped`` candidates (placeholder-screened) are
    counted and recorded, never written as findings."""

    candidate: SecretsCandidateFacts
    dropped: bool
    attributes: dict[str, object]
    title: str
    description: str


def _render_evidence_line(e: SecretsEvidence) -> str:
    """API-rendered explanation from enumerated facts only; worker prose is
    never stored or shown."""
    at = f"in {e.container_class}->{e.container_method}{e.container_descriptor}"
    if e.kind == "key-material-argument":
        return (f"worker-reported direct key-material route: literal reaches "
                f"key argument {e.arg_position} of {e.sink_class}->{e.sink_method} "
                f"at offset {e.sink_offset} {at}")
    if e.kind == "key-material-argument-derived":
        return (f"worker-reported MAY-depend derived route: literal enters "
                f"closed-world return-transform {e.transform_class}->{e.transform_method} "
                f"at offset {e.transform_offset}; its return reaches key "
                f"argument {e.arg_position} of {e.sink_class}->{e.sink_method} "
                f"at offset {e.sink_offset} {at}. Transform output bytes are "
                f"unmodelled; no decoded key value is claimed")
    return ("worker-reported comparison-suspect use: literal compared against "
            f"external input; offset {e.sink_offset} is the consuming branch "
            f"{at}, not the comparison invoke (review signal, not key-role "
            "evidence)")


def derive_candidate_attributes(
    result: SecretsAnalysisResult,
) -> tuple[DerivedCandidate, ...]:
    """The phase-1 contract, source-owned. Builds every gate attribute itself
    from validated facts; nothing from the worker passes through as an
    attribute. CONFIRMED and REJECTED are unreachable BY CONSTRUCTION:

    * ``format_and_entropy_ok`` is never written (missing, never False), so
      the gate's all-clauses-True pass is unreachable and no decisive failure
      can be misreported through a fallback rejection reason.
    * No other clause is ever written False here.
    * Placeholder-screened candidates are dropped and counted, never written
      with a False clause.

    The direct vs MAY-depend distinction is retained in the title/description
    (``as_gate_evidence`` does not carry ``security_use_basis``).
    """
    derived: list[DerivedCandidate] = []
    for cand in result.candidates:
        if cand.placeholder_screening == "placeholder":
            derived.append(DerivedCandidate(cand, True, {}, "", ""))
            continue
        attributes: dict[str, object] = {
            "located": True,
            # Worker-asserted screening; the API cannot recompute it without
            # the literal. Recorded as an attribute only in the True shape;
            # the False shape is the dropped path above.
            "not_placeholder": True,
        }
        basis = cand.security_use_basis
        if basis is not None:
            attributes["used_in_security_context"] = True
        if not cand.flow_complete:
            attributes["flow_incomplete"] = True
        # Phase-1 invariant: CONFIRMED/REJECTED unreachable. Raised, not
        # asserted, so it holds under python -O too.
        if "format_and_entropy_ok" in attributes:
            raise _InvariantViolation("format clause written in phase 1")
        if any(attributes.get(k) is False for k in _GATE_CLAUSE_KEYS):
            raise _InvariantViolation("a gate clause was written False in phase 1")

        cls, name, desc, off = cand.candidate_id
        lines = [_render_evidence_line(e) for e in cand.evidence]
        if basis == "may-depend-derived-route-only":
            use_text = ("Security use: MAY-depend derived route to a key "
                        "argument (transform output unmodelled).")
        elif basis == "direct-key-material-evidence":
            use_text = "Security use: direct key-material evidence."
        else:
            use_text = "Security use: not established (review-signal evidence only)."
        completeness = (
            "complete" if cand.flow_complete else "INCOMPLETE (absence not established)")
        title = f"Hardcoded-secret candidate in {cls}->{name} (manual review)"
        description = (
            f"Candidate literal declared at offset {off} in {cls}->{name}{desc}. "
            f"{use_text} Flow scan {completeness}. "
            "Placeholder screening is worker-asserted (the literal never "
            "leaves the worker). DEX completeness: "
            + ("worker-asserted complete (consistent ledger)"
               if result.dex_complete else
               "worker-asserted INCOMPLETE or ambiguous")
            + ". Evidence: " + "; ".join(lines)
        )
        if result.truncated:
            description += (" Payload TRUNCATED by the worker: unreported "
                            "candidates may exist; this is not a no-evidence result.")
        if result.conversion_failed:
            description += (
                f" Payload transport INCOMPLETE: {result.conversion_failed} "
                "worker-reported candidate(s) had detector evidence that "
                "could not be converted; this is not a complete scan.")
        derived.append(DerivedCandidate(cand, False, attributes, title, description))
    return tuple(derived)


@dataclass(frozen=True, slots=True)
class SecretsAccounting:
    """Truthful scan accounting with the source of each number named.
    Nonoverlapping categories; persistence belongs to the apply step.

    Two scan-level rules the apply step must honor:
    transport_complete=False must persist as a scan-level INCOMPLETE marker
    even when zero candidates transported (no candidate description exists
    to carry it); and an EMPTY result is never a no-secrets or safety
    claim, even when transport_complete=True - detection coverage is
    limited to what the detector screens for."""

    screened_total: int  # worker-asserted
    evidence_less: int  # worker-asserted; admitted without evidence, not transported
    merged: int  # worker-asserted; same const-string identity as another candidate
    conversion_failed: int  # worker-asserted; evidence existed, mapping failed
    transported: int  # API-counted from the payload
    placeholder_dropped: int  # API-counted at derivation
    truncated: bool  # worker-asserted; unreported candidates may exist
    transport_complete: bool  # API-derived; see class docstring rules


def accounting(result: SecretsAnalysisResult,
               derived: tuple[DerivedCandidate, ...]) -> SecretsAccounting:
    """Combine validated payload counts with derivation outcomes."""
    return SecretsAccounting(
        screened_total=result.screened_total,
        evidence_less=result.evidence_less,
        merged=result.merged,
        conversion_failed=result.conversion_failed,
        transported=len(result.candidates),
        placeholder_dropped=sum(1 for d in derived if d.dropped),
        truncated=result.truncated,
        transport_complete=result.transport_complete,
    )
