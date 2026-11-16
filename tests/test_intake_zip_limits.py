"""Adversarial tests for ZIP metadata accepted during APK intake."""

from __future__ import annotations

import io
import zipfile

import pytest

from mobius.services import intake
from mobius.services.errors import ApkInvalid


def _archive(entries: list[tuple[str, bytes]]) -> zipfile.ZipFile:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, payload in entries:
            archive.writestr(name, payload)
    buffer.seek(0)
    return zipfile.ZipFile(buffer)


def test_accepts_small_apk_container():
    with _archive([("AndroidManifest.xml", b"manifest"), ("classes.dex", b"dex")]) as archive:
        intake._validate_zip_container(archive)


def test_rejects_duplicate_entries():
    with _archive([("AndroidManifest.xml", b"one"), ("AndroidManifest.xml", b"two")]) as archive:
        with pytest.raises(ApkInvalid, match="duplicate ZIP entry"):
            intake._validate_zip_container(archive)


def test_rejects_unsafe_entry_paths():
    with _archive([("AndroidManifest.xml", b"manifest"), ("../escape", b"x")]) as archive:
        with pytest.raises(ApkInvalid, match="unsafe ZIP entry path"):
            intake._validate_zip_container(archive)


def test_rejects_excessive_entry_count(monkeypatch):
    monkeypatch.setattr(intake, "MAX_APK_ENTRIES", 1)
    with _archive([("AndroidManifest.xml", b"manifest"), ("classes.dex", b"dex")]) as archive:
        with pytest.raises(ApkInvalid, match="too many ZIP entries"):
            intake._validate_zip_container(archive)


def test_rejects_excessive_total_uncompressed_size(monkeypatch):
    monkeypatch.setattr(intake, "MAX_APK_UNCOMPRESSED_BYTES", 8)
    with _archive([("AndroidManifest.xml", b"manifest"), ("classes.dex", b"dex")]) as archive:
        with pytest.raises(ApkInvalid, match="total uncompressed"):
            intake._validate_zip_container(archive)


def test_rejects_excessive_compression_ratio(monkeypatch):
    monkeypatch.setattr(intake, "MAX_APK_COMPRESSION_RATIO", 2)
    with _archive([("AndroidManifest.xml", b"m" * (2 * 1024 * 1024))]) as archive:
        with pytest.raises(ApkInvalid, match="compression ratio"):
            intake._validate_zip_container(archive)


def test_rejects_oversized_manifest(monkeypatch):
    monkeypatch.setattr(intake, "MAX_MANIFEST_BYTES", 4)
    with _archive([("AndroidManifest.xml", b"12345")]) as archive:
        with pytest.raises(ApkInvalid, match="manifest size limit"):
            intake._validate_zip_container(archive)


def test_rejects_missing_manifest():
    with _archive([("classes.dex", b"dex")]) as archive:
        with pytest.raises(ApkInvalid, match="AndroidManifest"):
            intake._validate_zip_container(archive)
