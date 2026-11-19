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


# Verified against AOSP (see reports): PatternMatcher.match dispatch,
# matchGlobPattern, ParsedProviderUtils.parseProvider/parsePathPermission, and
# ContentProvider.enforceRead/WritePermissionInner. Semantics below mirror the
# enforcement code; where we cannot match a pattern type, we report UNKNOWN
# instead of guessing.
PATTERN_LITERAL = "literal"
PATTERN_PREFIX = "prefix"
PATTERN_SUFFIX = "suffix"
PATTERN_SIMPLE_GLOB = "simple_glob"
PATTERN_ADVANCED_GLOB = "advanced_glob"


def match_simple_glob(pattern: str, match: str) -> bool:
    """Direct port of AOSP PatternMatcher.matchGlobPattern (PATTERN_SIMPLE_GLOB).

    '.' matches any single char; 'x*' is zero or more repetitions of the
    preceding character x; '.*' is any sequence; '\\' escapes the next char.
    """
    np = len(pattern)
    if np <= 0:
        return len(match) <= 0
    nm = len(match)
    ip = im = 0
    next_char = pattern[0]
    while ip < np and im < nm:
        c = next_char
        ip += 1
        next_char = pattern[ip] if ip < np else "\0"
        escaped = c == "\\"
        if escaped:
            c = next_char
            ip += 1
            next_char = pattern[ip] if ip < np else "\0"
        if next_char == "*":
            if not escaped and c == ".":
                if ip >= np - 1:
                    return True  # trailing '.*' matches the rest
                ip += 1
                next_char = pattern[ip]
                if next_char == "\\":
                    ip += 1
                    next_char = pattern[ip] if ip < np else "\0"
                while match[im] != next_char:
                    im += 1
                    if im >= nm:
                        return False
                ip += 1
                next_char = pattern[ip] if ip < np else "\0"
                im += 1
            else:
                # zero or more occurrences of the character before '*'
                while im < nm and match[im] == c:
                    im += 1
                ip += 1
                next_char = pattern[ip] if ip < np else "\0"
        else:
            if c != "." and match[im] != c:
                return False
            im += 1
    if ip >= np and im >= nm:
        return True
    # match string finished but a trailing '.*' still counts as a match
    if ip == np - 2 and pattern[ip] == "." and pattern[ip + 1] == "*":
        return True
    return False


@dataclass(frozen=True, slots=True)
class PathPermission:
    """A <path-permission> element as enforcement sees it.

    ``read_permission``/``write_permission`` carry the parse-time resolution
    (each falls back to the element's general android:permission, per
    ParsedProviderUtils.parsePathPermission). An element with both None is
    ignored by enforcement (AOSP discards it at parse time); we keep it as
    evidence and skip it in resolution. ``pattern_type`` is one of the
    PATTERN_* constants above.
    """
    pattern: str
    pattern_type: str
    read_permission: str | None = None
    write_permission: str | None = None

    def matches(self, uri_path: str) -> bool | None:
        """True/False for implemented pattern types; None (unknown) for
        PATTERN_ADVANCED_GLOB, whose matcher we do not port."""
        if self.pattern_type == PATTERN_LITERAL:
            return uri_path == self.pattern
        if self.pattern_type == PATTERN_PREFIX:
            return uri_path.startswith(self.pattern)
        if self.pattern_type == PATTERN_SUFFIX:
            return uri_path.endswith(self.pattern)
        if self.pattern_type == PATTERN_SIMPLE_GLOB:
            return match_simple_glob(self.pattern, uri_path)
        return None  # advanced glob: unknown, never guessed


@dataclass(frozen=True, slots=True)
class Component:
    kind: str
    name: str
    exported: bool
    export_source: ExportSource
    permission: str | None = None
    intent_filters: tuple[IntentFilter, ...] = ()
    enabled: bool = True
    read_permission: str | None = None
    write_permission: str | None = None
    path_permissions: tuple[PathPermission, ...] = ()
    grant_uri_permissions: bool = False

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
class DeclaredPermission:
    """A <permission> element: this APK's own definition of a permission name."""

    name: str
    protection_level: str | None  # raw android:protectionLevel; None = platform default ("normal")


@dataclass(frozen=True, slots=True)
class ManifestSurface:
    """Everything RECON can establish from the manifest alone."""

    package_name: str
    version_name: str | None = None
    version_code: int | None = None
    min_sdk: int | None = None
    target_sdk: int | None = None
    permissions: tuple[str, ...] = ()
    declared_permissions: tuple[DeclaredPermission, ...] = ()
    application_permission: str | None = None
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


class ProtectionStatus(StrEnum):
    PROTECTED = "protected"
    UNPROTECTED = "unprotected"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class ProtectionVerdict:
    status: ProtectionStatus
    permission: str | None  # protecting permission name when PROTECTED
    basis: str


def effective_protection(
    surface: ManifestSurface,
    component: Component,
    operation: str,
    uri_path: str | None = None,
) -> ProtectionVerdict:
    """Effective protection for one provider operation ("read"/"write"), from the
    perspective of a caller holding NO permissions.

    Mirrors ContentProvider.enforceRead/WritePermissionInner (AOSP master):
    - component permission = op-specific attr, falling back to the provider's
      general permission, then the application permission (the parse-time
      resolution in ParsedProviderUtils.parseProvider).
    - Default access is allowed only when that component permission is null
      AND no path-permission with an op-specific permission matches the URI
      path. ALL path-permissions are iterated; any matching one with an
      op-specific permission protects (for a no-permission caller).
    - A path-permission whose op-specific permission is null is skipped by
      enforcement (it never removes the provider-level protection).
    - Advanced-glob patterns we cannot match yield UNKNOWN, never unprotected.
    URI grants are reported separately (grant_uri_permissions flag), not here.
    """
    if operation not in ("read", "write"):
        raise ValueError(f"operation must be 'read' or 'write', got {operation!r}")
    specific = component.read_permission if operation == "read" else component.write_permission
    component_perm = specific or component.permission or surface.application_permission

    if component_perm is not None:
        return _level_adjusted_verdict(
            surface, component_perm,
            "provider operation permission chain (op-specific -> provider -> application)",
        )

    if uri_path is not None:
        saw_unknown_match = False
        for pp in component.path_permissions:
            op_perm = pp.read_permission if operation == "read" else pp.write_permission
            if op_perm is None:
                continue  # skipped by enforcement (AOSP discards at parse time)
            matched = pp.matches(uri_path)
            if matched is None:
                saw_unknown_match = True  # advanced glob: cannot decide
                continue
            if matched:
                return _level_adjusted_verdict(
                    surface, op_perm,
                    f"matching path-permission {pp.pattern!r} ({pp.pattern_type})",
                )
        if saw_unknown_match:
            return ProtectionVerdict(
                ProtectionStatus.UNKNOWN, None,
                "path-permission uses an advanced glob we cannot match",
            )

    if uri_path is None and any(
        (pp.read_permission if operation == "read" else pp.write_permission) is not None
        for pp in component.path_permissions
    ):
        return ProtectionVerdict(
            ProtectionStatus.UNKNOWN, None,
            "provider declares path-permissions; a per-path verdict is required",
        )

    return ProtectionVerdict(
        ProtectionStatus.UNPROTECTED, None,
        "no operation permission, no provider/application permission, and no "
        "matching path-permission with an operation permission",
    )


# Own-declared levels that make a permission unobtainable for a differently
# signed caller: the only own-declared definitions that substantiate a
# protection boundary on their own. "signatureOrSystem"/"internal" are
# legacy/platform variants of the same signature-class boundary.
_STRONG_OWN_LEVELS = frozenset({"signature", "signatureOrSystem", "internal"})


def _level_adjusted_verdict(
    surface: ManifestSurface, permission: str, basis: str
) -> ProtectionVerdict:
    """A named permission protects only as strongly as its DEFINITION allows.

    - Own-declared signature-class: PROTECTED, with the exact scope stated.
    - Own-declared "normal" (including a missing protectionLevel attribute,
      whose platform default is normal): granted at install time to any app,
      so it cannot substantiate a boundary -> UNKNOWN.
    - Own-declared "dangerous": granted per user decision at runtime; neither
      blanket-dismissed nor robust -> UNKNOWN.
    - Not declared in this APK (platform or external definition): the level is
      unresolved here -> UNKNOWN. Never assumed obtainable, never assumed strong.
    """
    declaration = next(
        (d for d in surface.declared_permissions if d.name == permission), None
    )
    if declaration is None:
        return ProtectionVerdict(
            ProtectionStatus.UNKNOWN, permission,
            f"{basis}; permission {permission!r} is not declared in this APK, "
            "so its protection level is unresolved (platform or external "
            "definition, neither assumed obtainable nor assumed strong)",
        )
    base = (declaration.protection_level or "normal").split("|")[0].strip()
    if base in _STRONG_OWN_LEVELS:
        return ProtectionVerdict(
            ProtectionStatus.PROTECTED, permission,
            f"{basis}; own-declared protectionLevel "
            f"{declaration.protection_level!r}: only same-signature or "
            "platform-internal callers obtain it",
        )
    if base == "dangerous":
        return ProtectionVerdict(
            ProtectionStatus.UNKNOWN, permission,
            f"{basis}; own-declared protectionLevel 'dangerous': grantable to "
            "any app by user decision at runtime, so a strong boundary is not "
            "demonstrated",
        )
    return ProtectionVerdict(
        ProtectionStatus.UNKNOWN, permission,
        f"{basis}; own-declared protectionLevel "
        f"{declaration.protection_level!r} (base {base!r}): an install-time or "
        "unrecognized grant level cannot substantiate a protection boundary",
    )
