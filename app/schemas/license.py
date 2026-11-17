"""License token and status schemas."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    EmailStr,
    Field,
    field_validator,
    model_validator,
)

HEX_FINGERPRINT = r"^[a-f0-9]{64}$"
LICENSE_ID_PATTERN = r"^[A-Z0-9][A-Z0-9-]{5,63}$"


def _ensure_timezone(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


class LicensePayload(BaseModel):
    """The signed contents of a lifetime, single-device license."""

    model_config = ConfigDict(
        extra="forbid",
        str_strip_whitespace=True,
        frozen=True,
    )

    schema_version: int = Field(default=1, ge=1, le=100)
    key_id: str = Field(pattern=r"^[a-f0-9]{16,64}$")
    license_id: str = Field(pattern=LICENSE_ID_PATTERN)
    product: str = Field(min_length=1, max_length=64)
    edition: str = Field(default="standard", min_length=1, max_length=64)
    license_type: Literal["lifetime"] = "lifetime"
    device_limit: Literal[1] = 1
    device_fingerprint: str = Field(pattern=HEX_FINGERPRINT)
    customer_name: str = Field(min_length=1, max_length=255)
    customer_email: EmailStr | None = None
    issued_at: datetime
    not_before: datetime | None = None
    features: list[str] = Field(default_factory=list, max_length=64)
    metadata: dict[str, str] = Field(default_factory=dict)

    @field_validator("issued_at", "not_before")
    @classmethod
    def _normalize_timestamps(cls, value: datetime | None) -> datetime | None:
        return _ensure_timezone(value) if value is not None else None

    @field_validator("features")
    @classmethod
    def _validate_features(cls, value: list[str]) -> list[str]:
        cleaned: list[str] = []
        for item in value:
            feature = item.strip()
            if not feature or len(feature) > 64:
                raise ValueError("Features must be 1-64 characters long.")
            if feature not in cleaned:
                cleaned.append(feature)
        return cleaned

    @field_validator("metadata")
    @classmethod
    def _validate_metadata(cls, value: dict[str, str]) -> dict[str, str]:
        if len(value) > 32:
            raise ValueError("Metadata cannot contain more than 32 entries.")
        cleaned: dict[str, str] = {}
        for key, item in value.items():
            clean_key = key.strip()
            clean_value = item.strip()
            if not clean_key or len(clean_key) > 64:
                raise ValueError("Metadata keys must be 1-64 characters long.")
            if len(clean_value) > 512:
                raise ValueError("Metadata values cannot exceed 512 characters.")
            cleaned[clean_key] = clean_value
        return cleaned

    @model_validator(mode="after")
    def _validate_dates(self) -> LicensePayload:
        if self.not_before is not None and self.not_before < self.issued_at:
            raise ValueError("not_before cannot be earlier than issued_at.")
        return self


class LicenseSummary(BaseModel):
    license_id: str
    product: str
    edition: str
    license_type: Literal["lifetime"]
    device_limit: int
    customer_name: str
    customer_email: EmailStr | None = None
    features: list[str] = Field(default_factory=list)
    issued_at: datetime
    not_before: datetime | None = None

    @classmethod
    def from_payload(cls, payload: LicensePayload) -> LicenseSummary:
        return cls(
            license_id=payload.license_id,
            product=payload.product,
            edition=payload.edition,
            license_type=payload.license_type,
            device_limit=payload.device_limit,
            customer_name=payload.customer_name,
            customer_email=payload.customer_email,
            features=list(payload.features),
            issued_at=payload.issued_at,
            not_before=payload.not_before,
        )


class DeviceSummary(BaseModel):
    fingerprint: str
    short_id: str
    platform: str


class LicenseStatusResponse(BaseModel):
    activated: bool
    valid: bool
    reason: str | None = None
    license: LicenseSummary | None = None
    device: DeviceSummary
    activation_id: str | None = None
    activated_at: datetime | None = None
    last_verified_at: datetime | None = None
    checked_at: datetime


class LicenseRecoveryResponse(BaseModel):
    activated: bool
    valid: bool
    reason: str | None = None
    license_key: str | None = None
    device: DeviceSummary
    checked_at: datetime


class LicenseVerifyResponse(BaseModel):
    valid: Literal[True] = True
    license: LicenseSummary
    device: DeviceSummary
    key_id: str
    checked_at: datetime


class TrialStatusResponse(BaseModel):
    trial: Literal[True] = True
    valid: bool
    trial_days_remaining: int = Field(ge=0)
    trial_ends_at: datetime | None = None
    reason: str
    device: DeviceSummary
