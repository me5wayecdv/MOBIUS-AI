"""Runtime configuration, from environment only (NFR-SEC-4)."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

_DEFAULT_DB = "sqlite+pysqlite:///./data/mobius.db"
_DEFAULT_ROOT = "./data"


@dataclass(frozen=True, slots=True)
class Settings:
    db_url: str
    artifact_root: Path
    env: str = "development"

    @property
    def is_production(self) -> bool:
        return self.env.lower() in {"production", "prod"}

    @classmethod
    def from_env(cls) -> Settings:
        return cls(
            db_url=os.environ.get("MOBIUS_DB_URL", _DEFAULT_DB),
            artifact_root=Path(os.environ.get("MOBIUS_ARTIFACT_ROOT", _DEFAULT_ROOT)),
            env=os.environ.get("MOBIUS_ENV", "development"),
        )
