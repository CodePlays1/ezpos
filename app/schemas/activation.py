"""Activation and administrative request schemas."""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator

from app.schemas.license import DeviceSummary, LicenseSummary

FINGERPRINT_PATTERN = r"^[a-f0-9]{64}$"


class ClientDevice(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    fingerprint: str = Field(pattern=FINGERPRINT_PATTERN)
    platform: Literal["windows", "macos", "linux"]


class LicenseTokenRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    license_key: str = Field(min_length=32, max_length=32_768)
    device: ClientDevice

    @field_validator("license_key")
    @classmethod
    def _strip_whitespace(cls, value: str) -> str:
        return "".join(value.split())


class CustomerActivationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    username: str = Field(
        min_length=3,
        max_length=60,
        pattern=r"^[a-zA-Z0-9][a-zA-Z0-9._-]{2,59}$",
    )
    license_code: str = Field(min_length=40, max_length=80)
    device: ClientDevice

    @field_validator("username")
    @classmethod
    def _normalize_username(cls, value: str) -> str:
        return value.casefold()

    @field_validator("license_code")
    @classmethod
    def _normalize_license_code(cls, value: str) -> str:
        return "".join(value.split()).upper()


class CreateCustomerLicenseRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    username: str = Field(
        min_length=3,
        max_length=60,
        pattern=r"^[a-zA-Z0-9][a-zA-Z0-9._-]{2,59}$",
    )
    customer_name: str = Field(min_length=1, max_length=255)
    customer_email: EmailStr | None = Field(default=None, max_length=320)

    @field_validator("username")
    @classmethod
    def _normalize_username(cls, value: str) -> str:
        return value.casefold()


class CustomerLicenseResponse(BaseModel):
    license_id: str
    username: str
    customer_name: str
    customer_email: str | None
    device_fingerprint: str | None
    status: str
    created_at: datetime


class CreatedCustomerLicenseResponse(CustomerLicenseResponse):
    activation_code: str


class ActivationResponse(BaseModel):
    license_key: str | None = None
    activation_id: str
    already_activated: bool
    license: LicenseSummary
    device: DeviceSummary
    activated_at: datetime
    last_verified_at: datetime


class AdminActivationResponse(BaseModel):
    activation_id: str
    license_id: str
    product: str
    edition: str
    license_type: str
    customer_name: str
    customer_email: str | None = None
    device_fingerprint: str
    device_short_id: str
    key_id: str
    features: list[str] = Field(default_factory=list)
    activated_at: datetime
    last_verified_at: datetime
    status: str


class RevokeLicenseRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    license_id: str = Field(pattern=r"^[A-Z0-9][A-Z0-9-]{5,63}$")
    reason: str = Field(default="", max_length=500)


class RevokeLicenseResponse(BaseModel):
    license_id: str
    revoked: bool
    reason: str
    revoked_at: datetime


class DeactivateLicenseRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    license_id: str = Field(pattern=r"^[A-Z0-9][A-Z0-9-]{5,63}$")


class DeactivateLicenseResponse(BaseModel):
    license_id: str
    deactivated: bool
