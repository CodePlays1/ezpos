from __future__ import annotations

from typing import Literal

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field


class AdminSetupRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    setup_token: str = Field(min_length=32, max_length=128)
    username: str = Field(
        min_length=3,
        max_length=60,
        pattern=r"^[a-zA-Z0-9][a-zA-Z0-9._-]{2,59}$",
    )
    password: str = Field(min_length=12, max_length=128)
    signing_key_password: str | None = Field(default=None, min_length=1, max_length=256)


class AdminUnlockRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    signing_key_password: str = Field(min_length=1, max_length=256)


class BackupActivation(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str = Field(min_length=1, max_length=36)
    license_id: str = Field(min_length=1, max_length=64)
    token: str = Field(min_length=1, max_length=32768)
    product: str = Field(min_length=1, max_length=64)
    edition: str = Field(min_length=1, max_length=64)
    license_type: str = Field(min_length=1, max_length=32)
    customer_name: str = Field(min_length=1, max_length=255)
    customer_email: str | None = Field(default=None, max_length=320)
    device_fingerprint: str = Field(pattern=r"^[a-f0-9]{64}$")
    key_id: str = Field(min_length=1, max_length=64)
    features: list[str] = Field(max_length=128)
    issued_at: AwareDatetime
    activated_at: AwareDatetime
    last_verified_at: AwareDatetime
    status: str = Field(min_length=1, max_length=16)
    created_at: AwareDatetime
    updated_at: AwareDatetime


class BackupCustomerLicense(BaseModel):
    model_config = ConfigDict(extra="forbid")

    license_id: str = Field(min_length=1, max_length=64)
    username: str = Field(min_length=1, max_length=60)
    activation_code_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    customer_name: str = Field(min_length=1, max_length=255)
    customer_email: str | None = Field(default=None, max_length=320)
    device_fingerprint: str | None = Field(
        default=None, pattern=r"^[a-f0-9]{64}$"
    )
    status: str = Field(min_length=1, max_length=16)
    created_at: AwareDatetime


class BackupTrialRegistration(BaseModel):
    model_config = ConfigDict(extra="forbid")

    device_fingerprint: str = Field(pattern=r"^[a-f0-9]{64}$")
    platform: str = Field(min_length=1, max_length=32)
    started_at: AwareDatetime
    last_seen_at: AwareDatetime


class BackupRevokedLicense(BaseModel):
    model_config = ConfigDict(extra="forbid")

    license_id: str = Field(min_length=1, max_length=64)
    reason: str = Field(max_length=500)
    revoked_at: AwareDatetime


class LicenseBackupData(BaseModel):
    model_config = ConfigDict(extra="forbid")

    activations: list[BackupActivation] = Field(max_length=10000)
    customer_licenses: list[BackupCustomerLicense] = Field(max_length=10000)
    trial_registrations: list[BackupTrialRegistration] = Field(max_length=10000)
    revoked_licenses: list[BackupRevokedLicense] = Field(max_length=10000)


class LicenseBackup(BaseModel):
    model_config = ConfigDict(extra="forbid")

    format: Literal["ezpos-license-backup"]
    version: Literal[1]
    key_id: str = Field(pattern=r"^[a-f0-9]{16}$")
    created_at: AwareDatetime
    data: LicenseBackupData
    signature: str = Field(min_length=80, max_length=100)


class LicenseBackupImportResponse(BaseModel):
    restored: dict[str, int]
    preserved_existing: bool = True
