from __future__ import annotations

import pytest

from mobius.worker.runner import _DEX_BINARY, _RECON_BINARY, _tool_for


IMAGE = "ghcr.io/me5wayecdv/mobius-dex@sha256:" + "a" * 64


def test_dex_job_uses_only_the_registered_dex_image_and_networkless_limits(monkeypatch):
    monkeypatch.setenv("MOBIUS_DEX_IMAGE", IMAGE)
    binary, image, spec = _tool_for("dex_index", "/usr/bin/podman")

    assert binary == _DEX_BINARY
    assert image == IMAGE
    assert spec.name == "dex_index"
    assert spec.limits.network_enabled is False
    assert spec.limits.memory_mb == 4096
    assert spec.limits.timeout_seconds == 900
    assert spec.argv_for({}) == (
        _DEX_BINARY, "--input", "/work/input.apk", "--max-methods", "50000"
    )


def test_recon_job_keeps_its_own_image_and_limits(monkeypatch):
    image = "ghcr.io/me5wayecdv/mobius-recon@sha256:" + "b" * 64
    monkeypatch.setenv("MOBIUS_RECON_IMAGE", image)
    binary, actual_image, spec = _tool_for("recon_manifest", "/usr/bin/podman")

    assert binary == _RECON_BINARY
    assert actual_image == image
    assert spec.name == "recon_manifest"
    assert spec.limits.network_enabled is False


def test_worker_dispatch_rejects_unknown_job_kinds():
    with pytest.raises(RuntimeError, match="unsupported worker job kind"):
        _tool_for("arbitrary_command", "/usr/bin/podman")


def test_dex_dispatch_requires_an_immutable_image_reference(monkeypatch):
    monkeypatch.setenv("MOBIUS_DEX_IMAGE", "ghcr.io/example/mobius-dex:latest")
    with pytest.raises(ValueError, match="immutable sha256"):
        _tool_for("dex_index", "/usr/bin/podman")


def test_jadx_output_path_is_held_in_code():
    """The worker's jadx branch must refuse to run until a reviewed file-output mount
    contract and a verified output-tree cleanup exist - the hold is code, not docs."""
    from mobius.worker.runner import JADX_OUTPUT_HOLD_REASON, _run_jadx_job

    with pytest.raises(RuntimeError) as exc_info:
        _run_jadx_job()
    assert str(exc_info.value) == JADX_OUTPUT_HOLD_REASON
    assert "held" in JADX_OUTPUT_HOLD_REASON
