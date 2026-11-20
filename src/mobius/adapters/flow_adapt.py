"""Shared untrusted-APK adaptation: DEX entry selection and flow-IR adaptation.

This is the exact code path both the in-process provider service (local
development only) and the isolated provider-analysis worker run over attacker
supplied APK bytes. It lives in adapters so the worker entrypoint never
imports the service layer (DB, evidence, validation).

Bounds: entry sizes are checked BEFORE decompression, with per-entry and
aggregate budgets from adapters.dex, and method adaptation itself is bounded:
at most ``max_methods`` unique methods are adapted, app-bearing entries first
(manifest package heuristic, entry-level; never a trust boundary), instead of
adapting everything and refusing the APK afterwards. Nothing is silently
dropped: every discovered classes*.dex entry is accounted for in the coverage
ledger (``truncated-budget`` / ``skipped-budget`` when the method budget cuts
in), and any non-fully-parsed entry downgrades guard-absence claims to unknown
in the provider service.
"""
from __future__ import annotations

import re
import zipfile
from dataclasses import asdict, dataclass, replace
from io import BytesIO

from ..core.flow import flow_scan_from_androguard
from ..core.reachability import MethodRef
from .dex import MAX_DEX_BYTES, MAX_METHODS, MAX_TOTAL_DEX_BYTES, _DEX_ENTRY

_DEX_ENTRY_NUM = re.compile(r"^classes(\d*)\.dex$")


@dataclass(frozen=True, slots=True)
class DexBlobCoverage:
    """One classes*.dex entry's disposition. Nothing is silently dropped: every
    discovered entry is accounted for, and any non-parsed entry downgrades
    guard-absence claims to unknown in the provider service."""

    entry: str
    status: str  # parsed | failed-parse | skipped-oversized | skipped-aggregate
                 # | duplicate-entry | truncated-budget | skipped-budget
    size_bytes: int
    methods: int = 0       # NEWLY adapted unique methods from this entry
    duplicates: int = 0    # methods skipped because an earlier entry already
                           # supplied the same class (runtime first-wins)
    ambiguous: bool = False  # any duplicate class on this entry: first-wins
                           # is a classpath-order assumption (DexPathList
                           # element order), not a verification of what a
                           # device runtime loads; identical signatures can
                           # still hide different code. Coverage downgrades.
    error: str | None = None

    def describe(self) -> dict[str, object]:
        return {k: v for k, v in asdict(self).items() if v is not None}


@dataclass(frozen=True, slots=True)
class ClassOrigin:
    """Runtime-loading provenance for one adapted class.

    entry / entry_position identify the classes*.dex that supplied the class
    under first-wins resolution (numeric runtime order, resolved BEFORE the
    app-first budget order, so reordering never changes it). duplicated marks
    a class body also present in a LATER entry: first-wins is then a
    classpath-order assumption (DexPathList element order), not a
    verification of what a device runtime loads, and claims resting on this
    copy stay unknown.
    """

    entry: str
    entry_position: int
    duplicated: bool = False


def _dex_sort_key(name: str) -> int:
    """Runtime dex ordering: classes.dex, classes2.dex, ..., classesN.dex.

    Lexicographic order would put classes10.dex before classes2.dex.
    """
    digits = _DEX_ENTRY_NUM.fullmatch(name).group(1)
    return int(digits) if digits else 1


def dex_entries(apk_bytes: bytes) -> list[tuple[str, int, bytes | None, str | None]]:
    """Select root-level classes*.dex with the sizes checked BEFORE reading and
    an aggregate decompression bound (same constants as adapters.dex). Returns
    (entry, size, data-or-None, skip-reason) so skipped entries stay visible.

    Entries are processed in numeric runtime order. A repeated zip entry name
    (legal in ZIP) is kept visible as a duplicate instead of being re-read."""
    out: list[tuple[str, int, bytes | None, str | None]] = []
    with zipfile.ZipFile(BytesIO(apk_bytes)) as archive:
        total = 0
        seen: set[str] = set()
        for name in sorted((n for n in archive.namelist() if _DEX_ENTRY.fullmatch(n)),
                           key=_dex_sort_key):
            if name in seen:
                out.append((name, archive.getinfo(name).file_size, None,
                            "duplicate zip entry name"))
                continue
            seen.add(name)
            size = archive.getinfo(name).file_size
            if size > MAX_DEX_BYTES:
                out.append((name, size, None, f"exceeds {MAX_DEX_BYTES} byte limit"))
                continue
            if total + size > MAX_TOTAL_DEX_BYTES:
                out.append((name, size, None, "aggregate DEX budget exhausted"))
                continue
            total += size
            out.append((name, size, archive.read(name), None))
    return out


def adapt_code(apk_bytes: bytes, *, max_methods: int = MAX_METHODS, app_package: str | None = None):
    """Adapt selected classes*.dex into the core flow IR, bounded app-first.

    At most ``max_methods`` unique methods are adapted. Entries containing
    classes under ``app_package`` (the manifest package; a prioritization
    heuristic, not a trust boundary) spend the budget before library-only
    entries; within an entry, adaptation stays file order, so an app entry
    larger than the budget still loses methods. Duplicate-class first-wins
    claims are always resolved in numeric runtime order BEFORE the budget
    order is applied, so reordering never changes which copy of a class the
    analysis sees. Every entry's disposition lands in the ledger: ``parsed``,
    ``truncated-budget`` (budget cut inside the entry) or ``skipped-budget``
    (budget already exhausted), alongside the existing failure/skip statuses.
    """
    from androguard.core.dex import DEX

    if max_methods < 1:
        raise ValueError("max_methods must be at least 1")
    selected = list(dex_entries(apk_bytes))
    ledger_by_entry: dict[int, DexBlobCoverage] = {}
    # Phase 1: parse once and resolve first-wins claims in runtime order.
    # Duplicate class bodies across dex files: the runtime resolves a class
    # from the FIRST dex in classpath order (DexPathList searches its elements
    # front to back; AOSP dx documents the same policy as
    # CollisionPolicy.KEEP_FIRST). The WHOLE duplicate class is skipped, never
    # merged per-method: methods that exist only in the later copy do not
    # exist at runtime. ANY duplicate class marks ambiguity: first-wins is a
    # classpath-order assumption, not a runtime check.
    parsed: list[tuple[int, str, int, object, bool, list, int, bool]] = []
    seen_classes: dict[str, set[tuple[str, str]]] = {}
    superclasses: dict[str, str] = {}
    origins: dict[str, ClassOrigin] = {}
    duplicated_classes: set[str] = set()
    prefix = app_package + "." if app_package else None
    for position, (entry, size, raw, skip_reason) in enumerate(selected):
        if raw is None:
            reason = skip_reason or ""
            ledger_by_entry[position] = DexBlobCoverage(
                entry,
                "skipped-oversized" if "exceeds" in reason
                else "duplicate-entry" if "duplicate" in reason
                else "skipped-aggregate",
                size, error=skip_reason)
            continue
        try:
            vm = DEX(raw)
        except Exception as exc:
            ledger_by_entry[position] = DexBlobCoverage(entry, "failed-parse", size,
                                                        error=f"{type(exc).__name__}")
            continue
        claimed = []
        entry_duplicates = 0
        entry_ambiguous = False
        app_bearing = False
        for cls in vm.get_classes():
            dotted = cls.get_name()[1:-1].replace("/", ".")
            if app_package and (dotted == app_package or dotted.startswith(prefix)):
                app_bearing = True
            class_methods = list(cls.get_methods())
            if dotted in seen_classes:
                # ANY duplicate class marks ambiguity, identical signatures or
                # not: first-wins is a classpath-order assumption (DexPathList
                # element order), not a verification of what a given device
                # runtime loads, and identical signatures can still hide
                # different code, different guards.
                entry_duplicates += len(class_methods)
                entry_ambiguous = True
                duplicated_classes.add(dotted)
                continue
            seen_classes[dotted] = {(m.get_name(), m.get_descriptor()) for m in class_methods}
            origins[dotted] = ClassOrigin(entry, position)
            sup = cls.get_superclassname()
            if sup:
                superclasses[dotted] = sup[1:-1].replace("/", ".")
            claimed.append((dotted, class_methods))
        parsed.append((position, entry, size, vm, app_bearing, claimed,
                       entry_duplicates, entry_ambiguous))
    # Phase 2: adapt claimed methods app-first, bounded by max_methods. The
    # sort is stable, so runtime order is preserved within each group.
    parsed.sort(key=lambda item: 0 if item[4] else 1)
    methods = {}
    registers_sizes = {}
    try_regions = {}
    budget_exhausted = False
    for position, entry, size, vm, _app, claimed, entry_duplicates, entry_ambiguous in parsed:
        if budget_exhausted:
            ledger_by_entry[position] = DexBlobCoverage(
                entry, "skipped-budget", size, duplicates=entry_duplicates,
                ambiguous=entry_ambiguous, error="global method budget exhausted")
            continue
        entry_methods = 0
        for dotted, class_methods in claimed:
            for em in class_methods:
                ref = MethodRef(dotted, em.get_name(), em.get_descriptor())
                if ref in methods:
                    entry_duplicates += 1
                    continue
                if len(methods) >= max_methods:
                    budget_exhausted = True
                    break
                blocks = flow_scan_from_androguard(vm, em)
                if blocks is None:
                    continue
                entry_methods += 1
                methods[ref] = blocks
                code = em.get_code()
                registers_sizes[ref] = code.get_registers_size()
                # DEX try_item addresses are 16-bit code units; the flow IR
                # uses byte offsets.
                regions = tuple(
                    (t.get_start_addr() * 2, (t.get_start_addr() + t.get_insn_count()) * 2)
                    for t in (getattr(code, "tries", None) or ())
                )
                if regions:
                    try_regions[ref] = regions
            if budget_exhausted:
                break
        if budget_exhausted:
            ledger_by_entry[position] = DexBlobCoverage(
                entry,
                "truncated-budget" if entry_methods else "skipped-budget",
                size, methods=entry_methods, duplicates=entry_duplicates,
                ambiguous=entry_ambiguous, error="global method budget exhausted")
        else:
            ledger_by_entry[position] = DexBlobCoverage(
                entry, "parsed", size, methods=entry_methods,
                duplicates=entry_duplicates, ambiguous=entry_ambiguous,
                error="duplicate class body with divergent methods"
                if entry_ambiguous else None)
    # The ledger reports every discovered entry in runtime order, whatever the
    # adaptation order was.
    ledger = [ledger_by_entry[position] for position in range(len(selected))]
    if duplicated_classes:
        origins = {
            dotted: (replace(o, duplicated=True) if dotted in duplicated_classes else o)
            for dotted, o in origins.items()
        }
    return methods, registers_sizes, superclasses, try_regions, ledger, origins
