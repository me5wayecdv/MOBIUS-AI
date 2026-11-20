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
    # Experimental workflow knobs (defaults unchanged from the hardcoded
    # values they replace): per-call output cap, repair bound, auto-review cap.
    model_max_output_tokens: int = 1200
    model_max_repair_attempts: int = 2
    veritas_auto_max_reviews: int = 10
    jadx_cache_root: Path | None = None
    jadx_image: str | None = None
    # Explicit opt-in for the secrets-analysis enqueue route. Defaults OFF:
    # until a digest-pinned worker image is published and deployed, a queued
    # job would be claimed and terminally failed by an unconfigured worker.
    # Image digest presence alone is NOT treated as fleet capability.
    secrets_enqueue_enabled: bool = False

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
            model_max_output_tokens=int(os.environ.get("MOBIUS_MODEL_MAX_OUTPUT_TOKENS", "1200")),
            model_max_repair_attempts=int(os.environ.get("MOBIUS_MODEL_MAX_REPAIR_ATTEMPTS", "2")),
            veritas_auto_max_reviews=int(os.environ.get("MOBIUS_VERITAS_AUTO_MAX_REVIEWS", "10")),
            jadx_cache_root=Path(
                os.environ.get(
                    "MOBIUS_JADX_CACHE_ROOT",
                    str(Path(os.environ.get("MOBIUS_ARTIFACT_ROOT", _DEFAULT_ROOT)) / "jadx-cache"),
                )
            ).expanduser().resolve(),
            jadx_image=os.environ.get("MOBIUS_JADX_IMAGE") or None,
            secrets_enqueue_enabled=os.environ.get("MOBIUS_SECRETS_ENQUEUE_ENABLED") == "1",
        )
