"""Request-scoped dependencies.

Authentication is a STUB. There is no JWT, no password verification, no session table:
Phase 2 task T-049 owns that. What exists is the seam plus a refusal - the application
will not start in a production environment with stub auth, because a security tool with
fake authentication is worse than one with none: it would look protected.
"""

from __future__ import annotations

import os
from pathlib import Path

from fastapi import Header

from ..adapters.db import make_engine, make_session_factory
from ..adapters.models import Base
from ..services.artifacts import ArtifactStore
from ..services.model_provider import create_model_gateway
from .config import Settings


def _ensure_sqlite_parent(db_url: str) -> None:
    """Create the parent directory of a file-backed SQLite database, if there is one."""
    if not db_url.startswith("sqlite") or db_url.endswith(":memory:"):
        return
    _, _, path = db_url.partition(":///")
    if not path or path == ":memory:":
        return
    parent = Path(path).expanduser().parent
    if str(parent) not in {"", "."}:
        parent.mkdir(parents=True, exist_ok=True)


class AppContext:
    """Process-wide singletons. One engine, one store, one settings object."""

    def __init__(self, settings: Settings | None = None, *, create_schema: bool = True) -> None:
        self.settings = settings or Settings.from_env()
        if self.settings.env.lower() not in {"development", "dev", "test"}:
            raise RuntimeError(
                "refusing to start: MOBIUS currently supports stub identity only in "
                "development/test environments; configure real authentication before "
                f"using MOBIUS_ENV={self.settings.env!r}."
            )
        # Create the directories the process needs before opening the database. Without
        # this, a fresh checkout fails with `sqlite3.OperationalError: unable to open
        # database file`, which points at SQLite rather than at the missing directory.
        self.settings.artifact_root.mkdir(parents=True, exist_ok=True)
        _ensure_sqlite_parent(self.settings.db_url)
        self.engine = make_engine(self.settings.db_url)
        if create_schema:
            Base.metadata.create_all(self.engine)
        self.session_factory = make_session_factory(self.engine)
        self.store = ArtifactStore(self.settings.artifact_root)
        self.model_gateway = create_model_gateway(
            self.settings.model_provider,
            base_url=self.settings.model_base_url,
            model=self.settings.model_name,
            timeout_seconds=self.settings.model_timeout_seconds,
        )

    def session(self):
        return self.session_factory()


_context: AppContext | None = None


def get_context() -> AppContext:
    global _context
    if _context is None:
        _context = AppContext()
    return _context


def set_context(ctx: AppContext | None) -> None:
    """Test hook: replace the process context."""
    global _context
    _context = ctx


def analyst_id(x_analyst_id: str | None = Header(default=None)) -> str:
    """Identify the caller. STUB - see module docstring."""
    return x_analyst_id or os.environ.get("MOBIUS_DEV_ANALYST", "analyst-1")
