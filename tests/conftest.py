"""Shared fixtures.

Note: fixtures create rows through the services rather than by adding ORM objects
directly. Two reasons - it exercises real code paths, and SQLAlchemy without
``relationship()`` declarations does not order inserts by foreign key, so ad-hoc
multi-table adds fail intermittently (see mobius.services.intake module docstring).
"""

from __future__ import annotations

import io
import logging
import zipfile
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from mobius.api.deps import AppContext, set_context
from mobius.api.config import Settings
from mobius.api.app import create_app
from mobius.services.artifacts import ArtifactStore


# androguard logs every chunk it parses at DEBUG through loguru, which would bury pytest
# output. Silence it once, at import, rather than per test.
try:  # pragma: no cover - cosmetic
    from loguru import logger as _loguru

    _loguru.remove()
except ImportError:  # pragma: no cover
    pass
logging.getLogger("androguard").setLevel(logging.CRITICAL)


def make_apk(*, manifest: str | None = None, extra: dict[str, bytes] | None = None) -> bytes:
    """Build a minimal but structurally valid APK (a ZIP containing AndroidManifest.xml)."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("AndroidManifest.xml", manifest or "<manifest package='com.example'/>")
        zf.writestr("classes.dex", b"dex\n035\x00" + b"\x00" * 32)
        for name, data in (extra or {}).items():
            zf.writestr(name, data)
    return buf.getvalue()


@pytest.fixture()
def ctx(tmp_path):
    settings = Settings(
        db_url="sqlite+pysqlite:///:memory:",
        artifact_root=tmp_path / "artifacts",
        env="test",
    )
    context = AppContext(settings)
    set_context(context)
    yield context
    set_context(None)


@pytest.fixture()
def store(tmp_path) -> ArtifactStore:
    return ArtifactStore(tmp_path / "artifacts")


@pytest.fixture()
def session(ctx):
    s = ctx.session()
    try:
        yield s
        s.commit()
    finally:
        s.close()


@pytest.fixture()
def client(ctx) -> TestClient:
    return TestClient(create_app())


@pytest.fixture()
def future_iso() -> str:
    return (datetime.now(timezone.utc) + timedelta(days=7)).isoformat().replace("+00:00", "Z")


@pytest.fixture()
def past_iso() -> str:
    return (datetime.now(timezone.utc) - timedelta(days=1)).isoformat().replace("+00:00", "Z")
