"""Manifest decoding and surface derivation.

The binary-manifest case is the one that runs on real APKs, so it is tested against a
hand-encoded AXML fixture that androguard must also decode. Two independent implementations
agreeing on the same bytes is the strongest evidence available in an environment with no
sample APK.
"""

from __future__ import annotations

import io
import zipfile

import pytest

from _axml import encode, El, manifest_xml, ANDROID_NS as A, TYPE_INT_BOOLEAN, TYPE_STRING
from mobius.adapters.android_manifest import (
    ManifestParseError,
    extract_manifest_bytes,
    is_binary_axml,
    parse_apk,
    parse_manifest_bytes,
    parse_surface,
)
from mobius.core.manifest import (
    ExportSource,
    candidates,
    describe,
    recon_candidate_attributes,
)

TEXT_MANIFEST = b"""<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
          package="com.example.text" android:versionCode="9" android:versionName="2.0">
  <uses-sdk android:minSdkVersion="26" android:targetSdkVersion="33"/>
  <uses-permission android:name="android.permission.CAMERA"/>
  <application android:allowBackup="false" android:debuggable="true">
    <activity android:name=".Home" android:exported="true">
      <intent-filter>
        <action android:name="android.intent.action.MAIN"/>
        <category android:name="android.intent.category.LAUNCHER"/>
      </intent-filter>
    </activity>
    <activity android:name=".Deep" android:exported="true">
      <intent-filter>
        <action android:name="android.intent.action.VIEW"/>
        <category android:name="android.intent.category.BROWSABLE"/>
        <data android:scheme="https" android:host="example.com"/>
      </intent-filter>
    </activity>
    <activity android:name=".ImplicitFilter">
      <intent-filter><action android:name="android.intent.action.SEND"/></intent-filter>
    </activity>
    <activity android:name=".Internal"/>
    <service android:name=".Guarded" android:exported="true"
             android:permission="com.example.text.BIND"/>
  </application>
</manifest>
"""


def _apk(manifest: bytes) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("AndroidManifest.xml", manifest)
        zf.writestr("classes.dex", b"dex\n035\x00")
    return buf.getvalue()


# -- binary AXML path ------------------------------------------------------------------


def test_binary_manifest_detected():
    assert is_binary_axml(encode(manifest_xml())) is True
    assert is_binary_axml(TEXT_MANIFEST) is False


def test_binary_manifest_decodes_through_androguard():
    surface = parse_apk(_apk(encode(manifest_xml())))
    assert surface.decoded_from_binary is True
    assert surface.package_name == "com.example.demo"
    assert surface.version_code == 7
    assert surface.version_name == "1.2.3"
    assert surface.min_sdk == 24
    assert surface.target_sdk == 34
    assert surface.permissions == (
        "android.permission.INTERNET",
        "android.permission.READ_CONTACTS",
    )
    assert surface.debuggable is False
    assert surface.allow_backup is True
    assert surface.uses_cleartext_traffic is True


def test_binary_manifest_components():
    surface = parse_apk(_apk(encode(manifest_xml())))
    by_name = {c.name: c for c in surface.components}
    assert set(by_name) == {
        "com.example.demo.MainActivity",
        "com.example.demo.ExportActivity",
        "com.example.demo.SyncService",
        "com.example.demo.BootReceiver",
        "com.example.demo.FilesProvider",
    }
    launcher = by_name["com.example.demo.MainActivity"]
    assert launcher.kind == "activity" and launcher.exported and launcher.is_launcher

    service = by_name["com.example.demo.SyncService"]
    assert service.permission == "com.example.demo.BIND_SYNC"
    assert service.export_source is ExportSource.DECLARED

    provider = by_name["com.example.demo.FilesProvider"]
    assert provider.kind == "provider" and provider.exported is False


def test_receiver_without_exported_is_inferred_exported():
    """No android:exported but an intent-filter: the legacy platform default makes it
    reachable. Recorded as an inference, not as a declaration."""
    surface = parse_apk(_apk(encode(manifest_xml())))
    receiver = next(c for c in surface.components if c.kind == "receiver")
    assert receiver.exported is True
    assert receiver.export_source is ExportSource.INFERRED_INTENT_FILTER


# -- text path -------------------------------------------------------------------------


def test_text_manifest_parses_with_the_same_semantics():
    surface = parse_manifest_bytes(TEXT_MANIFEST)
    assert surface.decoded_from_binary is False
    assert surface.package_name == "com.example.text"
    assert surface.version_code == 9
    assert surface.min_sdk == 26 and surface.target_sdk == 33
    assert surface.permissions == ("android.permission.CAMERA",)
    assert surface.debuggable is True
    assert surface.allow_backup is False


def test_export_inference_rules():
    surface = parse_manifest_bytes(TEXT_MANIFEST)
    by_name = {c.name: c for c in surface.components}
    # explicit true
    assert by_name["com.example.text.Home"].export_source is ExportSource.DECLARED
    # intent-filter, no explicit flag -> inferred exported
    implicit = by_name["com.example.text.ImplicitFilter"]
    assert implicit.exported is True
    assert implicit.export_source is ExportSource.INFERRED_INTENT_FILTER
    # neither -> inferred not exported
    internal = by_name["com.example.text.Internal"]
    assert internal.exported is False
    assert internal.export_source is ExportSource.INFERRED_ABSENT


def test_deep_link_detected():
    surface = parse_manifest_bytes(TEXT_MANIFEST)
    deep = next(c for c in surface.components if c.name.endswith(".Deep"))
    assert deep.has_deep_link is True
    assert deep.intent_filters[0].hosts == ("example.com",)


def test_component_names_are_fully_qualified():
    surface = parse_manifest_bytes(TEXT_MANIFEST)
    assert all(c.name.startswith("com.example.text.") for c in surface.components)


# -- candidates and honesty ------------------------------------------------------------


def test_launcher_is_not_a_candidate():
    surface = parse_manifest_bytes(TEXT_MANIFEST)
    names = {c.name for c in candidates(surface)}
    assert "com.example.text.Home" not in names


def test_guarded_and_unexported_components_are_not_candidates():
    surface = parse_manifest_bytes(TEXT_MANIFEST)
    names = {c.name for c in candidates(surface)}
    assert "com.example.text.Guarded" not in names   # has permission
    assert "com.example.text.Internal" not in names  # not exported
    assert "com.example.text.Deep" in names
    assert "com.example.text.ImplicitFilter" in names


def test_recon_attributes_are_deliberately_incomplete():
    """RECON may assert only what the manifest shows.

    `caller_check_absent` and `sink_reachable` require reading code. If RECON claimed them,
    every exported component would confirm as a vulnerability - which is exactly the
    behaviour this project exists to avoid.
    """
    surface = parse_manifest_bytes(TEXT_MANIFEST)
    component = next(c for c in surface.components if c.name.endswith(".Deep"))
    attrs = recon_candidate_attributes(component)
    assert attrs == {"exported": True, "permission": None}
    assert "caller_check_absent" not in attrs
    assert "sink_reachable" not in attrs


def test_describe_reports_the_exclusions_it_makes():
    surface = parse_manifest_bytes(TEXT_MANIFEST)
    delta = describe(surface)
    assert delta.components == 5
    assert delta.excluded_launchers == 1
    assert delta.candidates == delta.unguarded - delta.excluded_launchers
    joined = " ".join(delta.notes)
    assert "launcher" in joined
    assert "debuggable" in joined
    assert "inferred" in joined


# -- failure modes ---------------------------------------------------------------------


def test_apk_without_manifest_is_rejected():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("readme.txt", "hi")
    with pytest.raises(ManifestParseError, match="no AndroidManifest"):
        extract_manifest_bytes(buf.getvalue())


def test_non_zip_is_rejected():
    with pytest.raises(ManifestParseError, match="cannot read APK"):
        extract_manifest_bytes(b"not a zip")


def test_root_must_be_manifest():
    with pytest.raises(ManifestParseError, match="expected <manifest>"):
        parse_surface(b"<application/>", decoded_from_binary=False)


def test_package_is_required():
    with pytest.raises(ManifestParseError, match="no package name"):
        parse_surface(b"<manifest/>", decoded_from_binary=False)


def test_malformed_xml_is_rejected():
    with pytest.raises(ManifestParseError, match="not well-formed"):
        parse_surface(b"<manifest package='x'>", decoded_from_binary=False)


def test_corrupt_binary_manifest_is_rejected():
    with pytest.raises(ManifestParseError):
        parse_manifest_bytes(b"\x03\x00\x08\x00" + b"\xff" * 40)


def test_component_with_explicit_false_stays_internal_despite_filter():
    """android:exported="false" beats the presence of an intent-filter."""
    xml = (
        b'<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="p.k">'
        b'<application><activity android:name=".A" android:exported="false">'
        b'<intent-filter><action android:name="x"/></intent-filter>'
        b"</activity></application></manifest>"
    )
    surface = parse_surface(xml, decoded_from_binary=False)
    assert surface.components[0].exported is False
    assert surface.components[0].export_source is ExportSource.DECLARED
