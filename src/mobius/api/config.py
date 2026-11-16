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
    model_provider: str = "disabled"
    model_base_url: str = "http://127.0.0.1:11434"
    model_name: str = ""
    model_timeout_seconds: int = 120

    @property
    def is_production(self) -> bool:
        return self.env.lower() in {"production", "prod"}

    @classmethod
    def from_env(cls) -> Settings:
        return cls(
            db_url=os.environ.get("MOBIUS_DB_URL", _DEFAULT_DB),
            artifact_root=Path(os.environ.get("MOBIUS_ARTIFACT_ROOT", _DEFAULT_ROOT)),
            env=os.environ.get("MOBIUS_ENV", "development"),
            model_provider=os.environ.get("MOBIUS_MODEL_PROVIDER", "disabled").lower(),
            model_base_url=os.environ.get("MOBIUS_MODEL_BASE_URL", "http://127.0.0.1:11434"),
            model_name=os.environ.get("MOBIUS_MODEL_NAME", ""),
            model_timeout_seconds=int(os.environ.get("MOBIUS_MODEL_TIMEOUT_SECONDS", "120")),
        )
