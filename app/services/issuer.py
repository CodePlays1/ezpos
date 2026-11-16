"""Vendor-side license issuance helpers.

These helpers must only be used where the Ed25519 private key is available,
for example on the vendor's offline signing workstation or in the CLI scripts.
They are never used by the deployed FastAPI verification service.
"""

from __future__ import annotations

import secrets
from collections.abc import Iterable, Mapping
from datetime import datetime

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from app.core.crypto import (
    LICENSE_TOKEN_PREFIX,
    REVOCATION_TOKEN_PREFIX,
    key_id_for_private_key,
    sign_token,
)
from app.core.time import utcnow
from app.schemas.license import LicensePayload
from app.services.revocation import RevocationDocument, RevocationEntry


def generate_license_id(prefix: str = "POS") -> str:
    clean_prefix = "".join(ch for ch in prefix.upper() if ch.isalnum()) or "POS"
    return f"{clean_prefix}-{secrets.token_hex(8).upper()}"


def build_license_payload(
    *,
    private_key: Ed25519PrivateKey,
    device_fingerprint: str,
    customer_name: str,
    product: str = "PharmaPOS",
    license_id: str | None = None,
    edition: str = "standard",
    customer_email: str | None = None,
    features: Iterable[str] | None = None,
    metadata: Mapping[str, str] | None = None,
    issued_at: datetime | None = None,
    not_before: datetime | None = None,
    schema_version: int = 1,
) -> LicensePayload:
    return LicensePayload(
        schema_version=schema_version,
        key_id=key_id_for_private_key(private_key),
        license_id=license_id or generate_license_id(),
        product=product,
        edition=edition,
        license_type="lifetime",
        device_limit=1,
        device_fingerprint=device_fingerprint.strip().lower(),
        customer_name=customer_name,
        customer_email=customer_email,
        issued_at=issued_at or utcnow(),
        not_before=not_before,
        features=list(features or []),
        metadata=dict(metadata or {}),
    )


def create_license_token(
    private_key: Ed25519PrivateKey, **kwargs
) -> tuple[str, LicensePayload]:
    payload = build_license_payload(private_key=private_key, **kwargs)
    token = sign_token(
        payload.model_dump(mode="json", exclude_none=True),
        private_key,
        prefix=LICENSE_TOKEN_PREFIX,
    )
    return token, payload


def create_revocation_token(
    private_key: Ed25519PrivateKey,
    entries: Iterable[RevocationEntry],
    *,
    issued_at: datetime | None = None,
) -> tuple[str, RevocationDocument]:
    document = RevocationDocument(
        schema_version=1,
        key_id=key_id_for_private_key(private_key),
        issued_at=issued_at or utcnow(),
        revoked=list(entries),
    )
    token = sign_token(
        document.model_dump(mode="json", exclude_none=True),
        private_key,
        prefix=REVOCATION_TOKEN_PREFIX,
    )
    return token, document
