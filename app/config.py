"""Application settings loaded from environment variables or a .env file."""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Annotated, Literal

from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict

PROJECT_ROOT = Path(__file__).resolve().parent.parent


class Settings(BaseSettings):
    """Runtime configuration for the licensing service.

    Every field can be overridden with a ``POS_LICENSE_`` prefixed environment
    variable, for example ``POS_LICENSE_PUBLIC_KEY_DIR``.
    """

    model_config = SettingsConfigDict(
        env_file=PROJECT_ROOT / ".env",
        env_file_encoding="utf-8",
        env_prefix="POS_LICENSE_",
        extra="ignore",
        case_sensitive=False,
    )

    app_name: str = "PharmaPOS License Backend"
    app_version: str = "1.0.0"
    environment: Literal["development", "testing", "production"] = "production"
    debug: bool = False
    host: str = "127.0.0.1"
    port: int = Field(default=8765, ge=1, le=65535)
    api_prefix: str = "/api/v1"

    database_url: str = (
        f"sqlite+aiosqlite:///{(PROJECT_ROOT / 'data' / 'licensing.db').as_posix()}"
    )
    public_key_dir: Path = PROJECT_ROOT / "keys" / "public"
    public_key_file: Path | None = None
    public_key_b64: str | None = None
    signing_private_key_b64: str | None = None
    signing_private_key_file: Path | None = None
    signing_key_password: str | None = None
    revocation_file: Path | None = None

    product: str = "PharmaPOS"
    license_schema_version: int = Field(default=1, ge=1)
    device_fingerprint_salt: str = "pharmapos-device-fingerprint-v1"
    device_override: str | None = None

    allowed_hosts: Annotated[list[str], NoDecode] = Field(
        default_factory=lambda: ["127.0.0.1", "localhost"]
    )
    cors_origins: Annotated[list[str], NoDecode] = Field(default_factory=list)
    enable_docs: bool | None = None
    log_level: str = "INFO"
    log_json: bool = True
    sql_echo: bool = False

    rate_limit_per_minute: int = Field(default=30, ge=0, le=10_000)
    admin_enabled: bool = False
    admin_api_key: str | None = None

    @field_validator(
        "public_key_file", "signing_private_key_file", "revocation_file", mode="before"
    )
    @classmethod
    def _blank_path_to_none(cls, value: object) -> object:
        if value is None or (isinstance(value, str) and not value.strip()):
            return None
        return value

    @field_validator("allowed_hosts", "cors_origins", mode="before")
    @classmethod
    def _parse_list(cls, value: object) -> object:
        """Accept JSON arrays, ``[a,b]`` with stripped quotes, or ``a,b``."""
        if not isinstance(value, str):
            return value
        text = value.strip()
        if not text:
            return []
        try:
            parsed = json.loads(text)
            if isinstance(parsed, list):
                return [str(item).strip() for item in parsed if str(item).strip()]
        except ValueError:
            pass
        text = text.strip("[]")
        return [
            part
            for item in text.split(",")
            if (part := item.strip().strip("'\""))
        ]

    @field_validator("database_url", mode="before")
    @classmethod
    def _normalize_database_url(cls, value: object) -> object:
        if not isinstance(value, str):
            return value
        if value.startswith("postgres://"):
            return value.replace("postgres://", "postgresql+asyncpg://", 1)
        if value.startswith("postgresql://"):
            return value.replace("postgresql://", "postgresql+asyncpg://", 1)
        return value

    @field_validator(
        "public_key_b64",
        "signing_private_key_b64",
        "signing_key_password",
        "device_override",
        "admin_api_key",
        mode="before",
    )
    @classmethod
    def _blank_string_to_none(cls, value: object) -> object:
        if value is None or (isinstance(value, str) and not value.strip()):
            return None
        return value

    @field_validator("api_prefix")
    @classmethod
    def _validate_api_prefix(cls, value: str) -> str:
        value = value.strip()
        if not value.startswith("/"):
            raise ValueError("api_prefix must start with '/'.")
        return value.rstrip("/") or "/"

    @field_validator("log_level")
    @classmethod
    def _validate_log_level(cls, value: str) -> str:
        value = value.strip().upper()
        if value not in {"CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG"}:
            raise ValueError(
                "log_level must be one of CRITICAL, ERROR, WARNING, INFO, DEBUG."
            )
        return value

    @field_validator("device_fingerprint_salt")
    @classmethod
    def _validate_salt(cls, value: str) -> str:
        value = value.strip()
        if len(value) < 16:
            raise ValueError("device_fingerprint_salt must be at least 16 characters.")
        return value

    @model_validator(mode="after")
    def _validate_security(self) -> Settings:
        if (
            self.environment == "production"
            and self.admin_enabled
            and self.admin_api_key
            and len(self.admin_api_key) < 32
        ):
            raise ValueError(
                "admin_api_key must be at least 32 characters in production."
            )
        if self.environment == "production":
            if self.debug:
                raise ValueError("debug must be false in production.")
            if self.device_override:
                raise ValueError("device_override is not allowed in production.")
        return self

    @property
    def docs_enabled(self) -> bool:
        if self.enable_docs is None:
            return self.environment != "production"
        return self.enable_docs


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return the process-wide settings instance."""

    return Settings()
