from __future__ import annotations

from datetime import UTC, datetime

import pytest

from app.core.crypto import KeyRing
from app.core.exceptions import RevocationListError
from app.services.issuer import create_revocation_token
from app.services.revocation import RevocationEntry, RevocationListStore


def test_signed_revocation_list_is_loaded(tmp_path, private_key):
    keyring = KeyRing([private_key.public_key()])
    path = tmp_path / "revocation.token"
    token, _document = create_revocation_token(
        private_key,
        [
            RevocationEntry(
                license_id="POS-REVOKE01",
                reason="refund",
                revoked_at=datetime.now(UTC),
            )
        ],
    )
    path.write_text(token, encoding="utf-8")

    store = RevocationListStore(keyring, path)
    store.verify_ready()

    assert store.is_revoked("POS-REVOKE01")
    assert not store.is_revoked("POS-OTHER001")


def test_tampered_revocation_list_is_rejected(tmp_path, private_key):
    keyring = KeyRing([private_key.public_key()])
    path = tmp_path / "revocation.token"
    token, _document = create_revocation_token(
        private_key, [RevocationEntry(license_id="POS-REVOKE01")]
    )
    path.write_text(token, encoding="utf-8")

    store = RevocationListStore(keyring, path)
    assert store.is_revoked("POS-REVOKE01")

    path.write_text(token[:-4] + "AAAA", encoding="utf-8")
    with pytest.raises(RevocationListError):
        store.is_revoked("POS-REVOKE01")


def test_missing_configured_revocation_list_fails_closed(tmp_path, private_key):
    keyring = KeyRing([private_key.public_key()])
    store = RevocationListStore(keyring, tmp_path / "missing.token")

    with pytest.raises(RevocationListError):
        store.verify_ready()
