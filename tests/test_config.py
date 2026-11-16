from __future__ import annotations

import pytest
from pydantic import ValidationError

from app.config import Settings


def test_render_postgres_url_is_normalized():
    settings = Settings(
        environment="testing",
        database_url="postgres://user:password@db.example.com/licenses",
    )
    assert settings.database_url == (
        "postgresql+asyncpg://user:password@db.example.com/licenses"
    )


def test_production_admin_api_key_must_be_strong():
    with pytest.raises(ValidationError, match="at least 32 characters"):
        Settings(
            environment="production",
            admin_enabled=True,
            admin_api_key="not-strong",
            signing_private_key_b64="a" * 100,
            signing_key_password="a-strong-password",
        )


def test_admin_dashboard_does_not_require_environment_api_key():
    settings = Settings(environment="testing", admin_enabled=True)
    assert settings.admin_api_key is None
