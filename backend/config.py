"""Central configuration for Iron360, sourced entirely from environment / .env.

No secrets are hardcoded here. Anything sensitive is read from the environment
and, where a default is unavoidable (dev only), generated at runtime and stored
in a gitignored file.
"""
from __future__ import annotations

import os
import secrets
from functools import lru_cache
from pathlib import Path

from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
DATA_DIR.mkdir(exist_ok=True)

# Load .env from project root if present (does not override real env vars).
load_dotenv(BASE_DIR / ".env")


def _bool(val: str | None, default: bool) -> bool:
    if val is None:
        return default
    return val.strip().lower() in {"1", "true", "yes", "on"}


class Settings:
    def __init__(self) -> None:
        self.env: str = os.getenv("IRON360_ENV", "development")
        self.host: str = os.getenv("IRON360_HOST", "127.0.0.1")
        self.port: int = int(os.getenv("IRON360_PORT", "8000"))

        self.jwt_secret: str = self._resolve_jwt_secret()
        self.jwt_ttl_minutes: int = int(os.getenv("IRON360_JWT_TTL_MINUTES", "480"))
        self.jwt_alg: str = "HS256"

        self.admin_username: str = os.getenv("IRON360_ADMIN_USERNAME", "admin")
        # Seed password is used ONCE to create the first admin, then hashed away.
        self.admin_password: str | None = os.getenv("IRON360_ADMIN_PASSWORD")

        origins = os.getenv("IRON360_ALLOWED_ORIGINS", "http://127.0.0.1:8000,http://localhost:8000")
        self.allowed_origins: list[str] = [o.strip() for o in origins.split(",") if o.strip()]

        self.anthropic_api_key: str | None = os.getenv("ANTHROPIC_API_KEY") or None
        # Point this at an OmniRoute / gateway endpoint (Anthropic-compatible /v1/messages)
        # to route through your own Claude instead of calling api.anthropic.com directly.
        self.anthropic_base_url: str | None = os.getenv("ANTHROPIC_BASE_URL") or None
        self.ai_model: str = os.getenv("IRON360_AI_MODEL", "claude-opus-4-8")
        self.ai_effort: str = os.getenv("IRON360_AI_EFFORT", "high")

        self.tool_timeout: int = int(os.getenv("IRON360_TOOL_TIMEOUT", "600"))
        self.executor_enabled: bool = _bool(os.getenv("IRON360_EXECUTOR_ENABLED"), True)

        self.db_url: str = f"sqlite:///{DATA_DIR / 'iron360.db'}"
        self.evidence_dir: Path = DATA_DIR / "evidence"
        self.evidence_dir.mkdir(exist_ok=True)

    def _resolve_jwt_secret(self) -> str:
        env_secret = os.getenv("IRON360_JWT_SECRET")
        if env_secret:
            return env_secret
        # Dev convenience: persist an auto-generated secret in a gitignored file so
        # tokens survive restarts without forcing the user to set one manually.
        secret_file = DATA_DIR / ".jwt_secret"
        if secret_file.exists():
            return secret_file.read_text().strip()
        generated = secrets.token_urlsafe(48)
        secret_file.write_text(generated)
        secret_file.chmod(0o600)
        return generated

    @property
    def ai_live(self) -> bool:
        """True when a real key or a gateway base URL is configured (live AI vs simulation)."""
        return bool(self.anthropic_api_key or self.anthropic_base_url)


@lru_cache
def get_settings() -> Settings:
    return Settings()
