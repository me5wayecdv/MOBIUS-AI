"""Shared untrusted-APK adaptation: DEX entry selection and flow-IR adaptation.

This is the exact code path both the in-process provider service (local
development only) and the isolated provider-analysis worker run over attacker
supplied APK bytes. It lives in adapters so the worker entrypoint never
imports the service layer (DB, evidence, validation).

Bounds: entry sizes are checked BEFORE decompression, with per-entry and
aggregate budgets from adapters.dex. Nothing is silently dropped: every
discovered classes*.dex entry is accounted for in the coverage ledger, and
any non-parsed entry downgrades guard-absence claims to unknown in the
provider service.
"""
from __future__ import annotations

import re
import zipfile
from dataclasses import asdict, dataclass
from io import BytesIO

from ..core.flow import flow_scan_from_androguard
from ..core.reachability import MethodRef
from .dex import MAX_DEX_BYTES, MAX_TOTAL_DEX_BYTES, _DEX_ENTRY

_DEX_ENTRY_NUM = re.compile(r"^classes(\d*)\.dex$")


@dataclass(frozen=True, slots=True)
class DexBlobCoverage:
    """One classes*.dex entry's disposition. Nothing is silently dropped: every
    discovered entry is accounted for, and any non-parsed entry downgrades
    guard-absence claims to unknown in the provider service."""

    entry: str
    status: str  # parsed | failed-parse | skipped-oversized | skipped-aggregate
                 # | duplicate-entry
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


def adapt_code(apk_bytes: bytes):
    """Adapt every selected classes*.dex into the core flow IR, accounting for
    each entry's disposition instead of silently dropping it."""
    from androguard.core.dex import DEX

    methods = {}
    registers_sizes = {}
    try_regions = {}
    superclasses: dict[str, str] = {}
    ledger: list[DexBlobCoverage] = []
    seen_classes: dict[str, set[tuple[str, str]]] = {}
    for entry, size, raw, skip_reason in dex_entries(apk_bytes):
        if raw is None:
            reason = skip_reason or ""
            ledger.append(DexBlobCoverage(
                entry,
                "skipped-oversized" if "exceeds" in reason
                else "duplicate-entry" if "duplicate" in reason
                else "skipped-aggregate",
                size, error=skip_reason))
            continue
        try:
            vm = DEX(raw)
        except Exception as exc:
            ledger.append(DexBlobCoverage(entry, "failed-parse", size,
                                          error=f"{type(exc).__name__}"))
            continue
        # Duplicate class bodies across dex files: the runtime resolves a
        # class from the FIRST dex in classpath order (DexPathList searches
        # its elements front to back; AOSP dx documents the same policy as
        # CollisionPolicy.KEEP_FIRST). The WHOLE duplicate class is skipped,
        # never merged per-method: methods that exist only in the later copy
        # do not exist at runtime. ANY duplicate class marks ambiguity:
        # first-wins is a classpath-order assumption, not a runtime check.
        entry_methods = 0
        entry_duplicates = 0
        entry_ambiguous = False
        for cls in vm.get_classes():
            dotted = cls.get_name()[1:-1].replace("/", ".")
            class_methods = list(cls.get_methods())
            if dotted in seen_classes:
                # ANY duplicate class marks ambiguity, identical signatures or
                # not: first-wins is a classpath-order assumption (DexPathList
                # element order), not a verification of what a given device
                # runtime loads, and identical signatures can still hide
                # different code, different guards.
                entry_duplicates += len(class_methods)
                entry_ambiguous = True
                continue
            seen_classes[dotted] = {(m.get_name(), m.get_descriptor()) for m in class_methods}
            sup = cls.get_superclassname()
            if sup:
                superclasses[dotted] = sup[1:-1].replace("/", ".")
            for em in class_methods:
                ref = MethodRef(dotted, em.get_name(), em.get_descriptor())
                if ref in methods:
                    entry_duplicates += 1
                    continue
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
        ledger.append(DexBlobCoverage(entry, "parsed", size, methods=entry_methods,
                                      duplicates=entry_duplicates,
                                      ambiguous=entry_ambiguous,
                                      error="duplicate class body with divergent methods"
                                      if entry_ambiguous else None))
    return methods, registers_sizes, superclasses, try_regions, ledger
