"""Signed offline revocation list support."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from threading import Lock

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from app.core.crypto import REVOCATION_TOKEN_PREFIX, KeyRing
from app.core.exceptions import LicenseError, RevocationListError
from app.core.time import ensure_utc


class RevocationEntry(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    license_id: str = Field(pattern=r"^[A-Z0-9][A-Z0-9-]{5,63}$")
    reason: str = Field(default="", max_length=500)
    revoked_at: datetime | None = None

    @field_validator("revoked_at")
    @classmethod
    def _normalize_revoked_at(
        cls, value: datetime | None
    ) -> datetime | None:
        return ensure_utc(value) if value is not None else None


class RevocationDocument(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: int = Field(default=1, ge=1, le=100)
    key_id: str = Field(pattern=r"^[a-f0-9]{16,64}$")
    issued_at: datetime
    revoked: list[RevocationEntry] = Field(default_factory=list)

    @field_validator("issued_at")
    @classmethod
    def _normalize_issued_at(cls, value: datetime) -> datetime:
        return ensure_utc(value)


class RevocationListStore:
    """Loads and caches a signed revocation token from disk."""

    def __init__(self, keyring: KeyRing, path: Path | None) -> None:
        self._keyring = keyring
        self._path = Path(path) if path else None
        self._cache: frozenset[str] = frozenset()
        self._cached_signature: tuple[int, int] | None = None
        self._lock = Lock()

    @property
    def configured(self) -> bool:
        return self._path is not None

    def verify_ready(self) -> None:
        self._load()

    def is_revoked(self, license_id: str) -> bool:
        return license_id in self._load()

    def _load(self) -> frozenset[str]:
        if self._path is None:
            return frozenset()

        with self._lock:
            try:
                stat = self._path.stat()
            except OSError as exc:
                raise RevocationListError(
                    f"Signed revocation list was not found: {self._path}"
                ) from exc

            signature = (stat.st_mtime_ns, stat.st_size)
            if self._cached_signature == signature:
                return self._cache

            try:
                text = self._path.read_text(encoding="utf-8")
            except OSError as exc:
                raise RevocationListError(
                    "Signed revocation list could not be read."
                ) from exc

            try:
                raw = self._keyring.verify_token(
                    text, prefix=REVOCATION_TOKEN_PREFIX
                )
                document = RevocationDocument.model_validate(raw)
            except (LicenseError, ValidationError) as exc:
                raise RevocationListError(
                    "Signed revocation list is invalid or has been tampered with."
                ) from exc

            if document.schema_version != 1:
                raise RevocationListError(
                    "Signed revocation list uses an unsupported schema version."
                )

            revoked = frozenset(entry.license_id for entry in document.revoked)
            self._cache = revoked
            self._cached_signature = signature
            return revoked
