from __future__ import annotations

import os
import secrets
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit


def _bool(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _csv(name: str) -> tuple[str, ...]:
    return tuple(item.strip() for item in os.getenv(name, "").split(",") if item.strip())


@dataclass(frozen=True)
class Settings:
    environment: str
    secret: str
    cookie_secure: bool
    allow_registration: bool
    allowed_hosts: tuple[str, ...]
    data_dir: Path
    database_path: Path
    upload_dir: Path
    llm_provider: str
    llm_base_url: str
    llm_api_key: str
    generation_model: str
    review_model: str
    blocked_brands: tuple[str, ...]

    @property
    def llm_ready(self) -> bool:
        parsed = urlsplit(self.llm_base_url)
        host = (parsed.hostname or "").lower()
        local_http = parsed.scheme == "http" and host in {"localhost", "127.0.0.1", "::1"}
        remote_https = parsed.scheme == "https" and bool(host and self.llm_api_key and self.llm_api_key != "ollama")
        return bool(self.generation_model and self.review_model and (local_http or remote_https))


def load_settings() -> Settings:
    environment = os.getenv("ENVIRONMENT", "development").strip().lower()
    secret = os.getenv("APP_SECRET", "").strip()
    if len(secret) < 32:
        if environment == "production":
            raise RuntimeError("APP_SECRET must contain at least 32 characters in production")
        secret = secrets.token_urlsafe(48)

    data_dir = Path(os.getenv("DATA_DIR", "./data")).expanduser().resolve()
    database_path = Path(os.getenv("DATABASE_PATH", str(data_dir / "guardrail.sqlite3"))).expanduser().resolve()
    upload_dir = Path(os.getenv("UPLOAD_DIR", str(data_dir / "uploads"))).expanduser().resolve()
    hosts = set(_csv("APP_ALLOWED_HOSTS"))
    render_host = os.getenv("RENDER_EXTERNAL_HOSTNAME", "").strip()
    if render_host:
        hosts.add(render_host)
    if not hosts:
        hosts.update({"localhost", "127.0.0.1", "testserver"})

    provider = os.getenv("LLM_PROVIDER", "ollama").strip().lower() or "ollama"
    if provider == "gemini":
        base_url = os.getenv(
            "GEMINI_BASE_URL", "https://generativelanguage.googleapis.com/v1beta/openai"
        ).strip().rstrip("/")
        api_key = os.getenv("GEMINI_API_KEY", "").strip()
        generation_model = os.getenv("GEMINI_MODEL", "gemini-3.8-flash").strip()
        review_model = os.getenv("GEMINI_REVIEW_MODEL", generation_model).strip()
    elif provider == "ollama":
        base_url = os.getenv("LLM_BASE_URL", "http://127.0.0.1:11434/v1").strip().rstrip("/")
        api_key = os.getenv("LLM_API_KEY", "").strip()
        generation_model = os.getenv("GENERATION_MODEL", "sentinel-local").strip()
        review_model = os.getenv("REVIEW_MODEL", "sentinel-local").strip()
    elif provider == "openai-compatible":
        base_url = os.getenv("LLM_BASE_URL", "https://api.openai.com/v1").strip().rstrip("/")
        api_key = os.getenv("LLM_API_KEY", "").strip()
        generation_model = os.getenv("GENERATION_MODEL", "").strip()
        review_model = os.getenv("REVIEW_MODEL", "").strip()
    else:
        raise RuntimeError("LLM_PROVIDER must be ollama, gemini, or openai-compatible")

    return Settings(
        environment=environment,
        secret=secret,
        cookie_secure=_bool("COOKIE_SECURE", environment == "production"),
        allow_registration=_bool("ALLOW_REGISTRATION", True),
        allowed_hosts=tuple(sorted(hosts)),
        data_dir=data_dir,
        database_path=database_path,
        upload_dir=upload_dir,
        llm_provider=provider,
        llm_base_url=base_url,
        llm_api_key=api_key,
        generation_model=generation_model,
        review_model=review_model,
        blocked_brands=_csv("BLOCKED_BRANDS"),
    )
