"""Request-scoped dependencies.

Authentication is a STUB. There is no JWT, no password verification, no session table:
Phase 2 task T-049 owns that. What exists is the seam plus a refusal - the application
will not start in a production environment with stub auth, because a security tool with
fake authentication is worse than one with none: it would look protected.
"""

from __future__ import annotations

import os

from fastapi import Header

from ..adapters.db import make_engine, make_session_factory
from ..adapters.models import Base
from ..services.artifacts import ArtifactStore
from .config import Settings


class AppContext:
    """Process-wide singletons. One engine, one store, one settings object."""

    def __init__(self, settings: Settings | None = None, *, create_schema: bool = True) -> None:
        self.settings = settings or Settings.from_env()
        if self.settings.is_production:
            raise RuntimeError(
                "refusing to start: stub authentication is enabled and MOBIUS_ENV="
                f"{self.settings.env!r}. Implement real auth (T-049) before deploying."
            )
        self.engine = make_engine(self.settings.db_url)
        if create_schema:
            Base.metadata.create_all(self.engine)
        self.session_factory = make_session_factory(self.engine)
        self.store = ArtifactStore(self.settings.artifact_root)

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
