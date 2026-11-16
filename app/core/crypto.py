"""Ed25519 license signing and verification.

Tokens are compact, URL-safe strings:

    POS1.<base64url(canonical-json-payload)>.<base64url(ed25519-signature)>

The exact payload bytes are signed, so verification never re-serialises
untrusted data. Private keys must never be deployed with the POS application.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from app.core.exceptions import (
    KeyRingError,
    PrivateKeyPasswordRequired,
    TokenFormatError,
    TokenSignatureError,
)

LICENSE_TOKEN_PREFIX = "POS1"
REVOCATION_TOKEN_PREFIX = "POSREV1"
MAX_TOKEN_LENGTH = 32_768
MAX_PAYLOAD_BYTES = 24_576
_B64URL_RE = re.compile(r"^[A-Za-z0-9_-]+={0,2}$")


def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(value: str) -> bytes:
    if not value or not _B64URL_RE.fullmatch(value):
        raise TokenFormatError("Token contains invalid base64url data.")
    padded = value + "=" * (-len(value) % 4)
    try:
        return base64.urlsafe_b64decode(padded)
    except (binascii.Error, ValueError) as exc:
        raise TokenFormatError("Token contains invalid base64url data.") from exc


def canonical_json(payload: Mapping[str, Any]) -> bytes:
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def normalize_token(value: str) -> str:
    if not isinstance(value, str):
        raise TokenFormatError("License token must be a string.")
    token = "".join(value.split())
    if not token:
        raise TokenFormatError("License token is empty.")
    if len(token) > MAX_TOKEN_LENGTH:
        raise TokenFormatError("License token is too large.")
    return token


def key_id_for_public_key(public_key: Ed25519PublicKey) -> str:
    raw = public_key.public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    return hashlib.sha256(raw).hexdigest()[:16]


def key_id_for_private_key(private_key: Ed25519PrivateKey) -> str:
    return key_id_for_public_key(private_key.public_key())


@dataclass(frozen=True)
class VerifyingKey:
    key_id: str
    key: Ed25519PublicKey
    source: str


class KeyRing:
    """An immutable set of trusted Ed25519 public keys."""

    def __init__(self, keys: Iterable[Ed25519PublicKey]) -> None:
        mapping: dict[str, Ed25519PublicKey] = {}
        for key in keys:
            if not isinstance(key, Ed25519PublicKey):
                raise KeyRingError("Only Ed25519 public keys are supported.")
            mapping[key_id_for_public_key(key)] = key
        if not mapping:
            raise KeyRingError("No license verification keys are configured.")
        self._keys: Mapping[str, Ed25519PublicKey] = MappingProxyType(mapping)

    @property
    def key_ids(self) -> tuple[str, ...]:
        return tuple(sorted(self._keys))

    def __contains__(self, key_id: str) -> bool:
        return key_id in self._keys

    def get(self, key_id: str) -> Ed25519PublicKey | None:
        return self._keys.get(key_id)

    def verify_token(
        self, token: str, *, prefix: str = LICENSE_TOKEN_PREFIX
    ) -> dict[str, Any]:
        """Verify a token against every trusted key and return its payload.

        Keys are tried directly instead of trusting the unverified ``key_id``
        field in the payload. The payload is parsed only after the signature
        has been verified.
        """

        normalized = normalize_token(token)
        parts = normalized.split(".")
        if len(parts) != 3 or parts[0] != prefix:
            raise TokenFormatError("The token format or prefix is invalid.")

        payload_bytes = b64url_decode(parts[1])
        signature = b64url_decode(parts[2])
        if len(payload_bytes) > MAX_PAYLOAD_BYTES:
            raise TokenFormatError("The signed payload is too large.")
        if len(signature) != 64:
            raise TokenFormatError("The Ed25519 signature has an invalid length.")

        matched_key_id: str | None = None
        for key_id, key in self._keys.items():
            try:
                key.verify(signature, payload_bytes)
            except InvalidSignature:
                continue
            matched_key_id = key_id
            break

        if matched_key_id is None:
            raise TokenSignatureError()

        try:
            payload = json.loads(payload_bytes.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise TokenFormatError("The signed payload is not valid JSON.") from exc
        if not isinstance(payload, dict):
            raise TokenFormatError("The signed payload must be a JSON object.")
        if payload.get("key_id") != matched_key_id:
            raise TokenSignatureError("The signing key identifier does not match.")
        return payload

    @classmethod
    def load(
        cls,
        *,
        directory: Path | None = None,
        file: Path | None = None,
        public_key_b64: str | None = None,
    ) -> KeyRing:
        keys: list[Ed25519PublicKey] = []

        if directory is not None:
            key_dir = Path(directory)
            if key_dir.exists():
                if not key_dir.is_dir():
                    raise KeyRingError(f"Public key directory is not a directory: {key_dir}")
                for pem_path in sorted(key_dir.glob("*.pem")):
                    try:
                        data = pem_path.read_bytes()
                    except OSError as exc:
                        raise KeyRingError(
                            f"Unable to read public key: {pem_path}"
                        ) from exc
                    keys.append(_load_public_key_pem(data, source=str(pem_path)))

        if file is not None:
            key_file = Path(file)
            if not key_file.is_file():
                raise KeyRingError(f"Public key file was not found: {key_file}")
            try:
                data = key_file.read_bytes()
            except OSError as exc:
                raise KeyRingError(f"Unable to read public key: {key_file}") from exc
            keys.append(_load_public_key_pem(data, source=str(key_file)))

        if public_key_b64:
            keys.append(_load_public_key_b64(public_key_b64))

        if not keys:
            raise KeyRingError(
                "No Ed25519 public keys configured. Run scripts/generate_keys.py "
                "and set POS_LICENSE_PUBLIC_KEY_DIR, POS_LICENSE_PUBLIC_KEY_FILE, "
                "or POS_LICENSE_PUBLIC_KEY_B64."
            )
        return cls(keys)


def _load_public_key_pem(data: bytes, *, source: str) -> Ed25519PublicKey:
    try:
        key = serialization.load_pem_public_key(data)
    except (ValueError, TypeError) as exc:
        raise KeyRingError(f"Invalid public key PEM: {source}") from exc
    if not isinstance(key, Ed25519PublicKey):
        raise KeyRingError(f"Public key is not Ed25519: {source}")
    return key


def _load_public_key_b64(value: str) -> Ed25519PublicKey:
    text = value.strip()
    raw: bytes | None = None
    for decoder in (base64.b64decode, base64.urlsafe_b64decode):
        try:
            raw = decoder(text, validate=True)
            break
        except (binascii.Error, ValueError):
            continue
    if raw is None or len(raw) != 32:
        raise KeyRingError("POS_LICENSE_PUBLIC_KEY_B64 must encode 32 raw bytes.")
    return Ed25519PublicKey.from_public_bytes(raw)


def sign_token(
    payload: Mapping[str, Any],
    private_key: Ed25519PrivateKey,
    *,
    prefix: str = LICENSE_TOKEN_PREFIX,
) -> str:
    if not isinstance(private_key, Ed25519PrivateKey):
        raise TypeError("An Ed25519 private key is required.")
    if not prefix or prefix.endswith("."):
        raise ValueError("Token prefix is invalid.")

    key_id = key_id_for_private_key(private_key)
    body_payload = dict(payload)
    existing_key_id = body_payload.get("key_id")
    if existing_key_id is not None and existing_key_id != key_id:
        raise ValueError("Payload key_id does not match the signing key.")

    body_payload["key_id"] = key_id
    body = canonical_json(body_payload)
    if len(body) > MAX_PAYLOAD_BYTES:
        raise ValueError("Signed payload is too large.")

    signature = private_key.sign(body)
    return f"{prefix}.{b64url_encode(body)}.{b64url_encode(signature)}"


def load_private_key(
    path: Path | str, *, password: str | None = None
) -> Ed25519PrivateKey:
    key_path = Path(path)
    try:
        data = key_path.read_bytes()
    except OSError as exc:
        raise KeyRingError(f"Unable to read private key: {key_path}") from exc

    password_bytes = password.encode("utf-8") if password else None
    try:
        key = serialization.load_pem_private_key(data, password=password_bytes)
    except TypeError as exc:
        if password_bytes is None:
            raise PrivateKeyPasswordRequired(
                f"Private key is encrypted and requires a password: {key_path}"
            ) from exc
        raise KeyRingError(f"Unable to decrypt private key: {key_path}") from exc
    except ValueError as exc:
        raise KeyRingError(
            f"Invalid private key or incorrect password: {key_path}"
        ) from exc

    if not isinstance(key, Ed25519PrivateKey):
        raise KeyRingError(f"Private key is not Ed25519: {key_path}")
    return key


def load_private_key_b64(
    value: str, *, password: str
) -> Ed25519PrivateKey:
    try:
        data = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise KeyRingError(
            "The configured signing private key is not valid base64."
        ) from exc
    try:
        key = serialization.load_pem_private_key(
            data, password=password.encode("utf-8")
        )
    except (TypeError, ValueError) as exc:
        raise KeyRingError(
            "The configured signing private key is invalid or its password "
            "is incorrect."
        ) from exc
    if not isinstance(key, Ed25519PrivateKey):
        raise KeyRingError("The configured signing key is not Ed25519.")
    return key


def encode_private_key(
    private_key: Ed25519PrivateKey, *, password: str | None = None
) -> bytes:
    encryption: serialization.KeySerializationEncryption
    if password:
        encryption = serialization.BestAvailableEncryption(password.encode("utf-8"))
    else:
        encryption = serialization.NoEncryption()
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=encryption,
    )


def encode_public_key(public_key: Ed25519PublicKey) -> bytes:
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def generate_keypair() -> tuple[Ed25519PrivateKey, Ed25519PublicKey]:
    private_key = Ed25519PrivateKey.generate()
    return private_key, private_key.public_key()


def write_file_atomic(path: Path | str, data: bytes, *, mode: int = 0o600) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    temporary = target.with_name(f".{target.name}.{os.getpid()}.tmp")
    try:
        with temporary.open("wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        try:
            os.chmod(temporary, mode)
        except OSError:
            pass
        os.replace(temporary, target)
    finally:
        try:
            if temporary.exists():
                temporary.unlink()
        except OSError:
            pass
