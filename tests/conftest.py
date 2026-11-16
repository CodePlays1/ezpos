from __future__ import annotations

import base64
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from app.config import Settings
from app.core.crypto import (
    encode_private_key,
    encode_public_key,
    generate_keypair,
    key_id_for_private_key,
)
from app.main import create_app
from app.services.issuer import create_license_token

TEST_ADMIN_KEY = "test-admin-key-0123456789"
TEST_SALT = "test-device-fingerprint-salt"
TEST_SIGNING_PASSWORD = "test-signing-password"


def make_settings(
    root: Path,
    private_key: Ed25519PrivateKey,
    *,
    device: str = "device-a",
    db_name: str = "test.db",
    admin_enabled: bool = True,
    revocation_file: Path | None = None,
    rate_limit_per_minute: int = 0,
) -> Settings:
    public_dir = root / "keys" / "public"
    public_dir.mkdir(parents=True, exist_ok=True)
    public_path = public_dir / f"{key_id_for_private_key(private_key)}.pem"
    public_path.write_bytes(encode_public_key(private_key.public_key()))

    return Settings(
        environment="testing",
        debug=False,
        database_url=f"sqlite+aiosqlite:///{(root / db_name).as_posix()}",
        public_key_dir=public_dir,
        public_key_file=None,
        public_key_b64=None,
        signing_private_key_b64=base64.b64encode(
            encode_private_key(private_key, password=TEST_SIGNING_PASSWORD)
        ).decode("ascii"),
        signing_key_password=TEST_SIGNING_PASSWORD,
        revocation_file=revocation_file,
        product="PharmaPOS",
        license_schema_version=1,
        device_fingerprint_salt=TEST_SALT,
        device_override=device,
        allowed_hosts=["testserver", "127.0.0.1", "localhost"],
        cors_origins=[],
        enable_docs=False,
        log_level="WARNING",
        log_json=False,
        sql_echo=False,
        rate_limit_per_minute=rate_limit_per_minute,
        admin_enabled=admin_enabled,
        admin_api_key=TEST_ADMIN_KEY if admin_enabled else None,
    )


@pytest.fixture
def private_key() -> Ed25519PrivateKey:
    private, _public = generate_keypair()
    return private


@pytest.fixture
def key_id(private_key: Ed25519PrivateKey) -> str:
    return key_id_for_private_key(private_key)


@pytest.fixture
def settings_factory(tmp_path: Path, private_key: Ed25519PrivateKey):
    def _factory(**overrides) -> Settings:
        return make_settings(tmp_path, private_key, **overrides)

    return _factory


@pytest.fixture
def settings(settings_factory) -> Settings:
    return settings_factory()


@pytest.fixture
def app(settings: Settings):
    return create_app(settings)


@pytest.fixture
def client(app):
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture
def issue(private_key: Ed25519PrivateKey):
    def _issue(fingerprint: str, **overrides):
        overrides.setdefault("customer_name", "Test Customer")
        return create_license_token(
            private_key, device_fingerprint=fingerprint, **overrides
        )

    return _issue
