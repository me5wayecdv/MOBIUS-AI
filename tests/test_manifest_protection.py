"""Effective provider protection, derived from observed Android enforcement:

- ContentProvider.enforceRead/WritePermissionInner (AOSP master): default access
  allowed only when the op-resolved component permission is null AND no matching
  path-permission carries an op permission; all path-permissions are iterated.
- ParsedProviderUtils (android-31): op attr -> element/provider permission ->
  application permission resolution; empty-permission path-permission discarded.
- PatternMatcher.matchGlobPattern (AOSP master): '.' any char, 'x*' repeats the
  preceding char, '.*' any sequence, backslash escapes.
"""
from mobius.adapters.android_manifest import parse_surface
from mobius.core.manifest import (
    PATTERN_SIMPLE_GLOB,
    Component,
    DeclaredPermission,
    ExportSource,
    ManifestSurface,
    PathPermission,
    ProtectionStatus,
    effective_protection,
    match_simple_glob,
)


def sig(*names):
    """Own-declared signature-level permissions: the only own declarations
    that substantiate a protection boundary on their own."""
    return tuple(DeclaredPermission(n, "signature") for n in names)

XML = """<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.example">
  <permission android:name="com.example.APP" android:protectionLevel="signature"/>
  <permission android:name="com.example.PROV" android:protectionLevel="signature"/>
  <permission android:name="com.example.READ" android:protectionLevel="signature"/>
  <permission android:name="com.example.DOC" android:protectionLevel="signature"/>
  <permission android:name="com.example.LOCKED" android:protectionLevel="signature"/>
  <application android:permission="com.example.APP">
    <provider android:name=".P" android:exported="true"
        android:authorities="com.example.p"
        android:permission="com.example.PROV"
        android:readPermission="com.example.READ"
        android:grantUriPermissions="true">
      <path-permission android:pathPrefix="/ignored" />
      <path-permission android:path="/locked" android:readPermission="com.example.LOCKED"/>
      <path-permission android:pathPattern="/doc/.*" android:permission="com.example.DOC"/>
    </provider>
  </application>
</manifest>"""


def test_parser_captures_protection_chain():
    surface = parse_surface(XML.encode(), decoded_from_binary=False)
    assert surface.application_permission == "com.example.APP"
    p = surface.by_kind("provider")[0]
    assert p.permission == "com.example.PROV"
    assert p.read_permission == "com.example.READ"
    assert p.write_permission is None
    assert p.grant_uri_permissions is True
    assert len(p.path_permissions) == 3
    by_pattern = {pp.pattern: pp for pp in p.path_permissions}
    # element-level fallback: general permission feeds both op slots
    assert by_pattern["/doc/.*"].read_permission == "com.example.DOC"
    assert by_pattern["/doc/.*"].write_permission == "com.example.DOC"
    # no perms at all: retained as evidence, skipped by enforcement
    assert by_pattern["/ignored"].read_permission is None


def test_component_permission_chain():
    surface = parse_surface(XML.encode(), decoded_from_binary=False)
    p = surface.by_kind("provider")[0]
    # read: op-specific wins over provider general and application
    v = effective_protection(surface, p, "read", "/notes")
    assert v.status == ProtectionStatus.PROTECTED and v.permission == "com.example.READ"
    # write: falls back to provider general permission
    v = effective_protection(surface, p, "write", "/notes")
    assert v.status == ProtectionStatus.PROTECTED and v.permission == "com.example.PROV"


def test_application_permission_is_last_resort():
    surface = ManifestSurface(package_name="com.example",
                              declared_permissions=sig("com.example.APP"),
                              application_permission="com.example.APP")
    p = Component(kind="provider", name="com.example.P", exported=True,
                  export_source=ExportSource.DECLARED)
    v = effective_protection(surface, p, "read")
    assert v.status == ProtectionStatus.PROTECTED and v.permission == "com.example.APP"
    bare = ManifestSurface(package_name="com.example")
    assert effective_protection(bare, p, "write").status == ProtectionStatus.UNPROTECTED


def test_read_protected_write_open_split():
    # readPermission set, everything else absent: write is UNPROTECTED.
    surface = ManifestSurface(package_name="com.example",
                              declared_permissions=sig("com.example.READ"))
    p = Component(kind="provider", name="com.example.P", exported=True,
                  export_source=ExportSource.DECLARED,
                  read_permission="com.example.READ")
    assert effective_protection(surface, p, "read").status == ProtectionStatus.PROTECTED
    assert effective_protection(surface, p, "write").status == ProtectionStatus.UNPROTECTED


def test_empty_path_permission_does_not_remove_protection():
    # Enforcement skips path-permissions with no op permission; the provider
    # chain still decides. (AOSP discards such elements at parse time.)
    surface = ManifestSurface(package_name="com.example",
                              declared_permissions=sig("com.example.PROV"))
    p = Component(kind="provider", name="com.example.P", exported=True,
                  export_source=ExportSource.DECLARED,
                  permission="com.example.PROV",
                  path_permissions=(PathPermission("/open", "prefix"),))
    v = effective_protection(surface, p, "read", "/open/x")
    assert v.status == ProtectionStatus.PROTECTED and v.permission == "com.example.PROV"


def test_matching_path_permission_protects_when_provider_open():
    surface = ManifestSurface(package_name="com.example",
                              declared_permissions=sig("com.example.LOCKED"))
    p = Component(kind="provider", name="com.example.P", exported=True,
                  export_source=ExportSource.DECLARED,
                  path_permissions=(
                      PathPermission("/locked", "literal",
                                     read_permission="com.example.LOCKED"),
                  ))
    v = effective_protection(surface, p, "read", "/locked")
    assert v.status == ProtectionStatus.PROTECTED and v.permission == "com.example.LOCKED"
    # its write side has no op permission: skipped -> write is unprotected
    assert effective_protection(surface, p, "write", "/locked").status == (
        ProtectionStatus.UNPROTECTED)
    # non-matching path: provider chain (empty) -> unprotected
    assert effective_protection(surface, p, "read", "/other").status == (
        ProtectionStatus.UNPROTECTED)


def test_unknown_path_position_with_path_permissions_present():
    surface = ManifestSurface(package_name="com.example")
    p = Component(kind="provider", name="com.example.P", exported=True,
                  export_source=ExportSource.DECLARED,
                  path_permissions=(
                      PathPermission("/locked", "literal",
                                     read_permission="com.example.LOCKED"),
                  ))
    assert effective_protection(surface, p, "read").status == ProtectionStatus.UNKNOWN


def test_advanced_glob_is_unknown_never_unprotected():
    surface = ManifestSurface(package_name="com.example")
    p = Component(kind="provider", name="com.example.P", exported=True,
                  export_source=ExportSource.DECLARED,
                  path_permissions=(
                      PathPermission("/x/%d", "advanced_glob",
                                     read_permission="com.example.X"),
                  ))
    assert effective_protection(surface, p, "read", "/x/5").status == (
        ProtectionStatus.UNKNOWN)


def test_simple_glob_matches_aosp_semantics():
    # '.' matches any single character
    assert match_simple_glob("/notes/.", "/notes/1")
    assert not match_simple_glob("/notes/.", "/notes/12")
    # 'x*' repeats the preceding character zero or more times
    assert match_simple_glob("/notes/*", "/notes/")
    assert match_simple_glob("/notes/*", "/notes///")
    assert not match_simple_glob("/notes/*", "/notes/1")
    # '.*' matches any sequence, including empty and mid-pattern
    assert match_simple_glob("/notes/.*", "/notes/1")
    assert match_simple_glob("/notes/.*", "/notes/")
    # AOSP dot-star consumes to the FIRST occurrence of the next pattern char
    # (no backtracking): '/.*/edit' stops at the first '/'.
    assert match_simple_glob("/.*/edit", "/a/edit")
    assert not match_simple_glob("/.*/edit", "/notes/1/edit")
    # backslash escapes: '\*' is a literal asterisk
    assert match_simple_glob("/a\\*b", "/a*b")
    assert not match_simple_glob("/a\\*b", "/aXXb")


def test_simple_glob_pattern_type_routes_to_port():
    pp = PathPermission("/notes/.*", PATTERN_SIMPLE_GLOB,
                        read_permission="com.example.R")
    assert pp.matches("/notes/1") is True
    assert pp.matches("/other") is False


def test_undeclared_permission_level_is_unresolved_not_protected():
    """Platform or externally defined permission: the level cannot be resolved
    from this APK, so protection adequacy is UNKNOWN (never assumed strong,
    never assumed obtainable)."""
    surface = ManifestSurface(package_name="com.example")
    p = Component(kind="provider", name="com.example.P", exported=True,
                  export_source=ExportSource.DECLARED,
                  permission="android.permission.READ_CONTACTS")
    v = effective_protection(surface, p, "read")
    assert v.status == ProtectionStatus.UNKNOWN
    assert v.permission == "android.permission.READ_CONTACTS"
    assert "not declared in this APK" in v.basis


def test_own_declared_normal_permission_cannot_substantiate_boundary():
    surface = ManifestSurface(package_name="com.example",
                              declared_permissions=(
                                  DeclaredPermission("com.example.WEAK", "normal"),))
    p = Component(kind="provider", name="com.example.P", exported=True,
                  export_source=ExportSource.DECLARED,
                  permission="com.example.WEAK")
    v = effective_protection(surface, p, "read")
    assert v.status == ProtectionStatus.UNKNOWN
    assert "install-time" in v.basis


def test_own_declared_dangerous_permission_is_unresolved():
    surface = ManifestSurface(package_name="com.example",
                              declared_permissions=(
                                  DeclaredPermission("com.example.RISK", "dangerous"),))
    p = Component(kind="provider", name="com.example.P", exported=True,
                  export_source=ExportSource.DECLARED,
                  permission="com.example.RISK")
    v = effective_protection(surface, p, "read")
    assert v.status == ProtectionStatus.UNKNOWN
    assert "runtime" in v.basis


def test_own_declared_signature_protects_with_exact_scope():
    surface = ManifestSurface(package_name="com.example",
                              declared_permissions=sig("com.example.STRONG"))
    p = Component(kind="provider", name="com.example.P", exported=True,
                  export_source=ExportSource.DECLARED,
                  permission="com.example.STRONG")
    v = effective_protection(surface, p, "read")
    assert v.status == ProtectionStatus.PROTECTED
    assert "same-signature" in v.basis


def test_parser_captures_declared_permission_levels():
    xml = b"""<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.example">
      <permission android:name="com.example.A" android:protectionLevel="signature|privileged"/>
      <permission android:name="com.example.B"/>
    </manifest>"""
    surface = parse_surface(xml, decoded_from_binary=False)
    by_name = {d.name: d for d in surface.declared_permissions}
    assert by_name["com.example.A"].protection_level == "signature|privileged"
    assert by_name["com.example.B"].protection_level is None  # platform default: normal


def test_binary_manifest_numeric_protection_level_is_mapped():
    """Binary AXML renders android:protectionLevel as a decimal string; the
    ProtectionInfo base values (0-3) must map to their names or a real
    signature declaration would fail closed to UNKNOWN on every real APK."""
    from _axml import encode, El, ANDROID_NS as A, TYPE_INT_DEC, TYPE_STRING
    from mobius.adapters.android_manifest import to_text_xml
    xml = El("manifest", attrs=[("", "package", TYPE_STRING, "com.example")], children=[
        El("permission", attrs=[(A, "name", TYPE_STRING, "com.example.SIG"),
                                (A, "protectionLevel", TYPE_INT_DEC, 2)]),
        El("application"),
    ])
    surface = parse_surface(to_text_xml(encode(xml)), decoded_from_binary=True)
    assert surface.declared_permissions[0].protection_level == "signature"


def test_numeric_protection_level_hex_and_unknown_forms():
    """Conservative numeric support: decimal AND hex renderings of the proven
    ProtectionInfo base values 0-3 map to names; anything else (flag bits,
    out-of-range numbers, unrecognized strings) stays raw and therefore never
    matches a known level downstream - the verdict stays UNKNOWN. No bitmask
    is applied, so a privileged modifier can never read as plain signature."""
    def level(raw: str):
        xml = (
            '<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.example">'
            f'<permission android:name="com.example.P" android:protectionLevel="{raw}"/>'
            "<application/></manifest>"
        )
        return parse_surface(xml.encode(), decoded_from_binary=True).declared_permissions[0].protection_level

    assert level("0") == "normal"
    assert level("1") == "dangerous"
    assert level("2") == "signature"
    assert level("3") == "signatureOrSystem"
    assert level("0x00000002") == "signature"
    assert level("0x00000003") == "signatureOrSystem"
    # unknown forms: never normalized to a known base level
    for raw in ("18", "0x00000012", "signature|privileged", "2|16", "0xGG", "\u00b2"):  # \u00b2 isdigit() but not int()-able
        assert level(raw) not in {"normal", "dangerous", "signature", "signatureOrSystem"}
