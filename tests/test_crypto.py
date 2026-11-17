from __future__ import annotations

import base64
import json

import pytest
from cryptography.hazmat.primitives import serialization

from app.core.crypto import (
    LICENSE_TOKEN_PREFIX,
    KeyRing,
    b64url_encode,
    canonical_json,
    generate_keypair,
    key_id_for_private_key,
    load_private_key_b64,
    sign_token,
)
from app.core.exceptions import (
    KeyRingError,
    TokenFormatError,
    TokenSignatureError,
)


def test_signed_token_round_trip(private_key):
    keyring = KeyRing([private_key.public_key()])
    token = sign_token({"license_id": "POS-ABC123", "value": 1}, private_key)

    assert token.startswith(f"{LICENSE_TOKEN_PREFIX}.")
    payload = keyring.verify_token(token)
    assert payload["license_id"] == "POS-ABC123"
    assert payload["key_id"] == key_id_for_private_key(private_key)


def test_canonical_json_is_deterministic():
    assert canonical_json({"b": 2, "a": 1}) == canonical_json({"a": 1, "b": 2})


def test_tampered_payload_is_rejected(private_key):
    keyring = KeyRing([private_key.public_key()])
    token = sign_token({"license_id": "POS-ABC123"}, private_key)
    prefix, _payload, signature = token.split(".")
    forged = canonical_json({"license_id": "POS-EVIL99", "key_id": key_id_for_private_key(private_key)})
    tampered = f"{prefix}.{b64url_encode(forged)}.{signature}"

    with pytest.raises(TokenSignatureError):
        keyring.verify_token(tampered)


def test_tampered_signature_is_rejected(private_key):
    keyring = KeyRing([private_key.public_key()])
    token = sign_token({"license_id": "POS-ABC123"}, private_key)
    prefix, payload, _signature = token.split(".")
    forged_signature = b64url_encode(b"\x00" * 64)

    with pytest.raises(TokenSignatureError):
        keyring.verify_token(f"{prefix}.{payload}.{forged_signature}")


def test_token_signed_by_an_untrusted_key_is_rejected(private_key):
    other_private, _ = generate_keypair()
    keyring = KeyRing([private_key.public_key()])
    token = sign_token({"license_id": "POS-ABC123"}, other_private)

    with pytest.raises(TokenSignatureError):
        keyring.verify_token(token)


def test_key_rotation_accepts_old_and_new_keys(private_key):
    new_private, new_public = generate_keypair()
    keyring = KeyRing([private_key.public_key(), new_public])

    old_token = sign_token({"license_id": "POS-OLD111"}, private_key)
    new_token = sign_token({"license_id": "POS-NEW111"}, new_private)

    assert keyring.verify_token(old_token)["license_id"] == "POS-OLD111"
    assert keyring.verify_token(new_token)["license_id"] == "POS-NEW111"
    assert len(keyring.key_ids) == 2


def test_malformed_tokens_are_rejected(private_key):
    keyring = KeyRing([private_key.public_key()])

    with pytest.raises(TokenFormatError):
        keyring.verify_token("not-a-token")
    with pytest.raises(TokenFormatError):
        keyring.verify_token("WRONG.aaaa.bbbb")


def test_sign_token_rejects_mismatched_key_id(private_key):
    with pytest.raises(ValueError):
        sign_token({"license_id": "POS-ABC123", "key_id": "f" * 16}, private_key)


def test_keyring_loads_pem_directory_and_base64(tmp_path, private_key):
    from app.core.crypto import encode_public_key

    public_dir = tmp_path / "public"
    public_dir.mkdir()
    (public_dir / "key.pem").write_bytes(encode_public_key(private_key.public_key()))
    token = sign_token({"ok": True}, private_key)

    from_dir = KeyRing.load(directory=public_dir)
    assert from_dir.verify_token(token)["ok"] is True

    raw = private_key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    from_b64 = KeyRing.load(public_key_b64=base64.b64encode(raw).decode())
    assert from_b64.verify_token(token)["ok"] is True


def test_keyring_rejects_empty_configuration(tmp_path):
    with pytest.raises(KeyRingError):
        KeyRing.load(directory=tmp_path / "missing")


def test_load_private_key_b64_accepts_pem_and_der():
    private_key, _ = generate_keypair()
    expected = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    encryption = serialization.BestAvailableEncryption(b"secret")

    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=encryption,
    )
    der = private_key.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=encryption,
    )

    for encoded in (base64.b64encode(pem), base64.b64encode(der)):
        loaded = load_private_key_b64(encoded.decode(), password="secret")
        assert (
            loaded.private_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PrivateFormat.Raw,
                encryption_algorithm=serialization.NoEncryption(),
            )
            == expected
        )


def test_load_private_key_b64_rejects_wrong_password():
    private_key, _ = generate_keypair()
    der = private_key.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(b"secret"),
    )

    with pytest.raises(KeyRingError):
        load_private_key_b64(base64.b64encode(der).decode(), password="wrong")


def test_verified_payload_is_the_signed_json(private_key):
    keyring = KeyRing([private_key.public_key()])
    token = sign_token({"nested": {"b": [2, 1], "a": True}}, private_key)
    payload = keyring.verify_token(token)

    assert json.dumps(payload, sort_keys=True) == json.dumps(
        {
            "nested": {"b": [2, 1], "a": True},
            "key_id": key_id_for_private_key(private_key),
        },
        sort_keys=True,
    )
