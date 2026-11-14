"""The attack surface read out of an AndroidManifest.xml.

Layer 1: data and pure derivation only. No zipfile, no XML parser, no androguard. The
adapter decodes bytes into these structures; everything below is a total function over them.

The important discipline here is the separation between what the manifest *declares* and
what other agents must *establish*. RECON can see that an activity is exported. RECON
cannot see whether the code behind it reaches a privileged sink, and must not pretend to.
`recon_candidate_attributes` therefore returns only observed attributes, which is why a
RECON-derived candidate can only ever reach INSUFFICIENT_EVIDENCE - never CONFIRMED. That
property is asserted in tests/test_recon.py, because it is the difference between this
project and a scanner.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from types import MappingProxyType
from typing import Mapping

COMPONENT_KINDS: tuple[str, ...] = ("activity", "service", "receiver", "provider")


class ExportSource(StrEnum):
    """How we decided a component is exported.

    Kept as three values rather than a boolean because "the manifest says exported=true" and
    "nobody declared it and Android's legacy default makes it exported" are different
    evidence, and a reviewer is entitled to see which one a finding rests on.
    """

    DECLARED = "declared"
    INFERRED_INTENT_FILTER = "inferred-intent-filter"
    INFERRED_ABSENT = "inferred-absent"


@dataclass(frozen=True, slots=True)
class IntentFilter:
    actions: tuple[str, ...] = ()
    categories: tuple[str, ...] = ()
    schemes: tuple[str, ...] = ()
    hosts: tuple[str, ...] = ()

    @property
    def is_launcher(self) -> bool:
        return (
            "android.intent.action.MAIN" in self.actions
            and "android.intent.category.LAUNCHER" in self.categories
        )

    @property
    def has_deep_link(self) -> bool:
        return bool(self.schemes or self.hosts)


@dataclass(frozen=True, slots=True)
class Component:
    kind: str
    name: str
    exported: bool
    export_source: ExportSource
    permission: str | None = None
    intent_filters: tuple[IntentFilter, ...] = ()
    enabled: bool = True

    @property
    def fully_qualified_name(self) -> str:
        return self.name

    @property
    def is_launcher(self) -> bool:
        return any(f.is_launcher for f in self.intent_filters)

    @property
    def has_deep_link(self) -> bool:
        return any(f.has_deep_link for f in self.intent_filters)


@dataclass(frozen=True, slots=True)
class ManifestSurface:
    """Everything RECON can establish from the manifest alone."""

    package_name: str
    version_name: str | None = None
    version_code: int | None = None
    min_sdk: int | None = None
    target_sdk: int | None = None
    permissions: tuple[str, ...] = ()
    components: tuple[Component, ...] = ()
    allow_backup: bool | None = None
    debuggable: bool = False
    uses_cleartext_traffic: bool | None = None
    network_security_config: str | None = None
    decoded_from_binary: bool = True

    # -- queries -----------------------------------------------------------------
    def exported(self) -> tuple[Component, ...]:
        return tuple(c for c in self.components if c.exported and c.enabled)

    def unguarded_exported(self) -> tuple[Component, ...]:
        """Exported, enabled, and not protected by an android:permission."""
        return tuple(c for c in self.exported() if not c.permission)

    def by_kind(self, kind: str) -> tuple[Component, ...]:
        return tuple(c for c in self.components if c.kind == kind)

    def launchers(self) -> tuple[Component, ...]:
        return tuple(c for c in self.components if c.is_launcher)

    @property
    def declares_debuggable(self) -> bool:
        return self.debuggable

    def summary(self) -> Mapping[str, object]:
        return MappingProxyType(
            {
                "package_name": self.package_name,
                "version_name": self.version_name,
                "version_code": self.version_code,
                "min_sdk": self.min_sdk,
                "target_sdk": self.target_sdk,
                "components": len(self.components),
                "exported": len(self.exported()),
                "unguarded_exported": len(self.unguarded_exported()),
                "permissions": len(self.permissions),
                "debuggable": self.debuggable,
                "allow_backup": self.allow_backup,
                "uses_cleartext_traffic": self.uses_cleartext_traffic,
            }
        )


def recon_candidate_attributes(component: Component) -> dict[str, object]:
    """Gate attributes RECON is entitled to assert, and no others.

    Deliberately omits ``caller_check_absent`` and ``sink_reachable``: both require reading
    the code, which is SPECTRE's job. Supplying them here - even as a guess - is how a
    scanner ends up claiming every exported activity is a vulnerability.

    ``permission`` is passed as the declared value or ``None``. The gate's ``_is_empty``
    predicate treats ``None`` as satisfied, which is correct: no declared permission *is*
    the observation.
    """
    return {
        "exported": component.exported,
        "permission": component.permission,
    }


def candidates(surface: ManifestSurface) -> tuple[Component, ...]:
    """Components worth investigating: exported, enabled, unprotected, not the launcher.

    The launcher exclusion is a heuristic, not a proof. It removes the single most common
    false positive in Android scanning (the app's own entry screen), and every excluded
    component is still recorded as an observation so the decision is visible rather than
    silent.
    """
    return tuple(c for c in surface.unguarded_exported() if not c.is_launcher)


@dataclass(frozen=True, slots=True)
class SurfaceDelta:
    """What the surface implies for the investigation, with counts the UI can trust."""

    components: int = 0
    exported: int = 0
    unguarded: int = 0
    candidates: int = 0
    excluded_launchers: int = 0
    notes: tuple[str, ...] = field(default_factory=tuple)


def describe(surface: ManifestSurface) -> SurfaceDelta:
    unguarded = surface.unguarded_exported()
    cands = candidates(surface)
    launchers = [c for c in unguarded if c.is_launcher]
    notes: list[str] = []
    if launchers:
        notes.append(
            f"{len(launchers)} exported launcher component(s) excluded as candidates: "
            "an app's own entry screen is reachable only by the user tapping it"
        )
    if surface.debuggable:
        notes.append("manifest declares android:debuggable=true")
    if surface.allow_backup is True:
        notes.append("manifest declares android:allowBackup=true")
    if surface.uses_cleartext_traffic is True:
        notes.append("manifest permits cleartext HTTP traffic")
    inferred = [c for c in surface.components if c.export_source is not ExportSource.DECLARED]
    if inferred:
        notes.append(
            f"{len(inferred)} component(s) have no explicit android:exported; "
            "export status was inferred from the platform default"
        )
    return SurfaceDelta(
        components=len(surface.components),
        exported=len(surface.exported()),
        unguarded=len(unguarded),
        candidates=len(cands),
        excluded_launchers=len(launchers),
        notes=tuple(notes),
    )
