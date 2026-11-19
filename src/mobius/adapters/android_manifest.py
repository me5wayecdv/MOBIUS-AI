"""Decode an APK's AndroidManifest.xml into the Layer-1 surface model.

Two input formats, one output shape:

* **Binary AXML** - what is actually inside an APK. Decoded with androguard 4.x, which is
  the tool docs/ANDROID_SECURITY_METHODOLOGY.md §2 already specifies for RECON. It is pure
  Python and needs no JDK, which is why RECON is the one adapter that can run here.
* **Plain XML** - already-decoded manifests (JADX/Apktool output, hand-written fixtures).

Both converge on the same ElementTree walk, so there is exactly one place where manifest
semantics are interpreted. That matters: a binary-only and a text-only code path would drift
apart, and the drift would show up as findings that appear or vanish depending on how the
manifest was extracted.
"""

from __future__ import annotations

import io
import xml.etree.ElementTree as ET
import zipfile
from typing import Final

from ..core.manifest import (
    DeclaredPermission,
    COMPONENT_KINDS,
    PATTERN_ADVANCED_GLOB,
    PATTERN_LITERAL,
    PATTERN_PREFIX,
    PATTERN_SIMPLE_GLOB,
    PATTERN_SUFFIX,
    Component,
    ExportSource,
    IntentFilter,
    ManifestSurface,
    PathPermission,
)

ANDROID_NS: Final = "http://schemas.android.com/apk/res/android"
AXML_MAGIC: Final[bytes] = b"\x03\x00\x08\x00"
MANIFEST_ENTRY: Final = "AndroidManifest.xml"

# Providers default to exported for targetSdk < 17. v1 only supports modern targets, and the
# inference is recorded as INFERRED_ABSENT either way so a reviewer can see the assumption.
_PROVIDER_LEGACY_EXPORTED_BELOW_TARGET: Final = 17


def _silence_androguard() -> None:
    """Stop androguard logging every chunk it parses.

    It logs at DEBUG through loguru, which ignores the stdlib logging configuration and
    writes to stderr regardless - so an otherwise quiet service produces thousands of lines
    per manifest. Disabled at import, once.
    """
    try:
        from loguru import logger
    except ImportError:  # pragma: no cover - androguard always pulls loguru
        return
    logger.disable("androguard")


_silence_androguard()


class ManifestParseError(Exception):
    """The bytes are not a manifest we can read. Translated at the service boundary."""


def extract_manifest_bytes(apk_bytes: bytes) -> bytes:
    """Pull AndroidManifest.xml out of the APK zip."""
    try:
        with zipfile.ZipFile(io.BytesIO(apk_bytes)) as zf:
            return zf.read(MANIFEST_ENTRY)
    except KeyError as exc:
        raise ManifestParseError(f"APK contains no {MANIFEST_ENTRY}") from exc
    except (zipfile.BadZipFile, OSError) as exc:
        raise ManifestParseError(f"cannot read APK: {exc}") from exc


def is_binary_axml(data: bytes) -> bool:
    return data[:4] == AXML_MAGIC


def to_text_xml(data: bytes) -> bytes:
    """Return plain XML for either input format."""
    if not is_binary_axml(data):
        return data
    try:
        from androguard.core.axml import AXMLPrinter
    except ImportError as exc:  # pragma: no cover - dependency guard
        raise ManifestParseError(
            "binary manifest requires androguard; install it with `pip install androguard`"
        ) from exc
    try:
        printer = AXMLPrinter(data)
        if not printer.is_valid():
            raise ManifestParseError("androguard rejected the binary manifest")
        rendered = printer.get_xml()
    except ManifestParseError:
        raise
    except Exception as exc:  # androguard raises a variety of internal errors
        raise ManifestParseError(f"androguard failed to decode the manifest: {exc}") from exc
    return rendered if isinstance(rendered, bytes) else str(rendered).encode()


# -- helpers ---------------------------------------------------------------------------


def _tagname(element: ET.Element) -> str:
    tag = element.tag
    return tag.rsplit("}", 1)[-1] if "}" in tag else tag


def _android(element: ET.Element, name: str) -> str | None:
    """Read an android:-namespaced attribute, tolerating an unprefixed rendering.

    androguard's AXMLPrinter emits ``xmlns:android="..."`` but writes the attributes
    themselves without the ``android:`` prefix, so a strict ``{uri}name`` lookup finds
    nothing and every android: attribute silently reads as absent - which would make a
    fully exported app look inert. The bare-name fallback costs nothing and is safe here:
    the only unprefixed attribute in a manifest is ``package`` on the root, which is read
    by name directly.
    """
    value = element.get(f"{{{ANDROID_NS}}}{name}")
    if value is None:
        value = element.get(name)
    return value.strip() if isinstance(value, str) else value


def _as_bool(value: str | None) -> bool | None:
    if value is None:
        return None
    lowered = value.strip().lower()
    if lowered in {"true", "1"}:
        return True
    if lowered in {"false", "0"}:
        return False
    return None


def _as_int(value: str | None) -> int | None:
    if value is None or not value.strip():
        return None
    text = value.strip()
    try:
        return int(text, 0)
    except ValueError:
        try:
            return int(float(text))
        except ValueError:
            return None


def _qualify(name: str, package: str) -> str:
    if not name:
        return name
    if name.startswith("."):
        return f"{package}{name}"
    if "." not in name:
        return f"{package}.{name}"
    return name


def _filters(element: ET.Element) -> tuple[IntentFilter, ...]:
    filters: list[IntentFilter] = []
    for child in element:
        if _tagname(child) != "intent-filter":
            continue
        actions: list[str] = []
        categories: list[str] = []
        schemes: list[str] = []
        hosts: list[str] = []
        for item in child:
            kind = _tagname(item)
            if kind == "action":
                name = _android(item, "name")
                if name:
                    actions.append(name)
            elif kind == "category":
                name = _android(item, "name")
                if name:
                    categories.append(name)
            elif kind == "data":
                for value, bucket in (
                    (_android(item, "scheme"), schemes),
                    (_android(item, "host"), hosts),
                ):
                    if value and value not in bucket:
                        bucket.append(value)
        filters.append(
            IntentFilter(
                actions=tuple(actions),
                categories=tuple(categories),
                schemes=tuple(schemes),
                hosts=tuple(hosts),
            )
        )
    return tuple(filters)


def _component(element: ET.Element, kind: str, package: str, target_sdk: int | None) -> Component:
    raw_name = _android(element, "name") or ""
    filters = _filters(element)
    declared = _as_bool(_android(element, "exported"))
    enabled = _as_bool(_android(element, "enabled"))

    if declared is not None:
        exported, source = declared, ExportSource.DECLARED
    elif filters:
        # Legacy platform default: a component with an intent filter is reachable.
        exported, source = True, ExportSource.INFERRED_INTENT_FILTER
    elif kind == "provider" and target_sdk is not None and target_sdk < _PROVIDER_LEGACY_EXPORTED_BELOW_TARGET:
        exported, source = True, ExportSource.INFERRED_ABSENT
    else:
        exported, source = False, ExportSource.INFERRED_ABSENT

    path_permissions: list[PathPermission] = []
    grant_uri = _as_bool(_android(element, "grantUriPermissions")) or False
    if kind == "provider":
        for child in element:
            tag = _tagname(child)
            if tag == "path-permission":
                # ParsedProviderUtils.parsePathPermission: op-specific attrs fall
                # back to the element's general permission; pattern priority is
                # advanced > pattern > prefix > suffix > literal path.
                general = _android(child, "permission")
                read_perm = _android(child, "readPermission") or general
                write_perm = _android(child, "writePermission") or general
                pattern = _android(child, "pathAdvancedPattern")
                ptype = PATTERN_ADVANCED_GLOB
                if pattern is None:
                    pattern, ptype = _android(child, "pathPattern"), PATTERN_SIMPLE_GLOB
                if pattern is None:
                    pattern, ptype = _android(child, "pathPrefix"), PATTERN_PREFIX
                if pattern is None:
                    pattern, ptype = _android(child, "pathSuffix"), PATTERN_SUFFIX
                if pattern is None:
                    pattern, ptype = _android(child, "path"), PATTERN_LITERAL
                if pattern is not None:
                    path_permissions.append(PathPermission(
                        pattern=pattern,
                        pattern_type=ptype,
                        read_permission=read_perm,
                        write_permission=write_perm,
                    ))
            elif tag == "grant-uri-permission":
                grant_uri = True

    return Component(
        kind=kind,
        name=_qualify(raw_name, package),
        exported=exported,
        export_source=source,
        permission=_android(element, "permission"),
        intent_filters=filters,
        enabled=True if enabled is None else enabled,
        read_permission=_android(element, "readPermission"),
        write_permission=_android(element, "writePermission"),
        path_permissions=tuple(path_permissions),
        grant_uri_permissions=grant_uri,
    )


# -- main entry points -----------------------------------------------------------------


# android:protectionLevel base values (ProtectionInfo constants). Binary AXML
# renders the attribute numerically - aapt emits a decimal string in the XML
# dump, but hex renderings ("0x00000002") occur across tooling, so both exact
# numeric forms of the proven base values 0-3 are accepted. Flag bits (e.g.
# 0x10 privileged) are NOT masked off: an unrecognized value stays raw and
# never equals a known level downstream, so the verdict stays UNKNOWN.
_PROTECTION_LEVEL_BASE = {
    0: "normal",
    1: "dangerous",
    2: "signature",
    3: "signatureOrSystem",
}


def _normalize_protection_level(value: str | None) -> str | None:
    if value is None:
        return None
    v = value.strip()
    number: int | None = None
    if v.isascii() and v.isdigit():  # isdigit() alone admits non-ASCII digits ("²")
        number = int(v)
    elif v.lower().startswith("0x"):
        try:
            number = int(v, 16)
        except ValueError:
            number = None
    if number is not None and number in _PROTECTION_LEVEL_BASE:
        return _PROTECTION_LEVEL_BASE[number]
    return v


def parse_surface(xml_bytes: bytes, *, decoded_from_binary: bool = True) -> ManifestSurface:
    """Walk plain XML into a ManifestSurface. Total function over well-formed manifests."""
    try:
        root = ET.fromstring(xml_bytes)
    except ET.ParseError as exc:
        raise ManifestParseError(f"manifest is not well-formed XML: {exc}") from exc

    if _tagname(root) != "manifest":
        raise ManifestParseError(f"root element is <{_tagname(root)}>, expected <manifest>")

    package = (root.get("package") or "").strip()
    if not package:
        raise ManifestParseError("manifest declares no package name")

    min_sdk: int | None = None
    target_sdk: int | None = None
    permissions: list[str] = []
    declared: list[DeclaredPermission] = []
    components: list[Component] = []
    application: ET.Element | None = None

    for child in root:
        tag = _tagname(child)
        if tag == "permission":
            name = _android(child, "name")
            if name:
                declared.append(DeclaredPermission(
                    name=name,
                    protection_level=_normalize_protection_level(
                        _android(child, "protectionLevel"))))
        elif tag == "uses-sdk":
            min_sdk = _as_int(_android(child, "minSdkVersion"))
            target_sdk = _as_int(_android(child, "targetSdkVersion"))
        elif tag in {"uses-permission", "uses-permission-sdk-23"}:
            name = _android(child, "name")
            if name and name not in permissions:
                permissions.append(name)
        elif tag == "application":
            application = child

    allow_backup: bool | None = None
    debuggable = False
    cleartext: bool | None = None
    nsc: str | None = None

    if application is not None:
        allow_backup = _as_bool(_android(application, "allowBackup"))
        debuggable = bool(_as_bool(_android(application, "debuggable")))
        cleartext = _as_bool(_android(application, "usesCleartextTraffic"))
        nsc = _android(application, "networkSecurityConfig")
        for child in application:
            tag = _tagname(child)
            if tag in COMPONENT_KINDS:
                components.append(_component(child, tag, package, target_sdk))
            elif tag == "activity-alias":
                components.append(_component(child, "activity", package, target_sdk))

    return ManifestSurface(
        package_name=package,
        declared_permissions=tuple(declared),
        version_name=_android(root, "versionName"),
        version_code=_as_int(_android(root, "versionCode")),
        min_sdk=min_sdk,
        target_sdk=target_sdk,
        permissions=tuple(permissions),
        application_permission=_android(application, "permission") if application is not None else None,
        components=tuple(components),
        allow_backup=allow_backup,
        debuggable=debuggable,
        uses_cleartext_traffic=cleartext,
        network_security_config=nsc,
        decoded_from_binary=decoded_from_binary,
    )


def parse_apk(apk_bytes: bytes) -> ManifestSurface:
    """Full path: APK bytes -> surface."""
    manifest = extract_manifest_bytes(apk_bytes)
    binary = is_binary_axml(manifest)
    return parse_surface(to_text_xml(manifest), decoded_from_binary=binary)


def parse_manifest_bytes(manifest_bytes: bytes) -> ManifestSurface:
    """Manifest bytes only (binary or text), without the surrounding zip."""
    binary = is_binary_axml(manifest_bytes)
    return parse_surface(to_text_xml(manifest_bytes), decoded_from_binary=binary)
