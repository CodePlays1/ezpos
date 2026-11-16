"""License verification, activation, and status orchestration."""

from __future__ import annotations

import hmac
import logging
from dataclasses import dataclass
from datetime import timedelta

from pydantic import ValidationError
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import Settings
from app.core.crypto import (
    LICENSE_TOKEN_PREFIX,
    KeyRing,
    normalize_token,
)
from app.core.device import DeviceIdentity
from app.core.exceptions import (
    DeviceAlreadyActivatedError,
    DeviceMismatchError,
    LicenseAlreadyActivatedError,
    LicenseError,
    LicenseNotYetValidError,
    LicensePayloadError,
    LicenseRevokedError,
    UnsupportedLicenseVersionError,
    WrongProductError,
)
from app.core.time import utcnow
from app.db import repository
from app.db.models import Activation
from app.schemas.license import LicensePayload
from app.services.revocation import RevocationListStore

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class VerifiedLicense:
    payload: LicensePayload
    key_id: str
    token: str


@dataclass(frozen=True)
class ActivationOutcome:
    activation: Activation
    payload: LicensePayload
    already_activated: bool


@dataclass(frozen=True)
class StatusOutcome:
    activation: Activation | None
    payload: LicensePayload | None
    valid: bool
    reason: str | None


class LicenseValidator:
    def __init__(
        self,
        settings: Settings,
        keyring: KeyRing,
        revocations: RevocationListStore,
    ) -> None:
        self.settings = settings
        self.keyring = keyring
        self.revocations = revocations

    def verify(self, token: str, device_fingerprint: str) -> VerifiedLicense:
        normalized = normalize_token(token)
        raw = self.keyring.verify_token(normalized, prefix=LICENSE_TOKEN_PREFIX)

        try:
            payload = LicensePayload.model_validate(raw)
        except ValidationError as exc:
            details = [
                {
                    "field": ".".join(str(part) for part in error["loc"]),
                    "message": error["msg"],
                }
                for error in exc.errors()
            ]
            raise LicensePayloadError(details=details) from exc

        if payload.schema_version != self.settings.license_schema_version:
            raise UnsupportedLicenseVersionError(
                "This license uses an unsupported schema version."
            )
        if payload.product != self.settings.product:
            raise WrongProductError()
        if not hmac.compare_digest(
            payload.device_fingerprint, device_fingerprint.lower()
        ):
            raise DeviceMismatchError()

        now = utcnow()
        if payload.issued_at > now + timedelta(minutes=10):
            raise LicensePayloadError(
                "The license issue time is in the future. Check the system clock."
            )
        if payload.not_before is not None and now < payload.not_before:
            raise LicenseNotYetValidError()
        if self.revocations.is_revoked(payload.license_id):
            raise LicenseRevokedError()

        return VerifiedLicense(payload=payload, key_id=payload.key_id, token=normalized)


class LicenseService:
    def __init__(self, settings: Settings, keyring: KeyRing) -> None:
        self.settings = settings
        self.keyring = keyring
        self.revocations = RevocationListStore(keyring, settings.revocation_file)
        self.validator = LicenseValidator(settings, keyring, self.revocations)

    def verify_presented_token(
        self, token: str, device: DeviceIdentity
    ) -> VerifiedLicense:
        return self.validator.verify(token, device.fingerprint)

    async def activate(
        self, session: AsyncSession, token: str, device: DeviceIdentity
    ) -> ActivationOutcome:
        verified = self.validator.verify(token, device.fingerprint)
        license_id = verified.payload.license_id
        await repository.ensure_trial_consumed(
            session, device.fingerprint, device.platform
        )

        if await repository.is_license_revoked(session, license_id):
            raise LicenseRevokedError()

        existing = await repository.get_activation_by_license_id(session, license_id)
        now = utcnow()
        if existing is not None:
            if not hmac.compare_digest(
                existing.device_fingerprint, device.fingerprint
            ):
                raise LicenseAlreadyActivatedError()
            _apply_payload(existing, verified)
            existing.last_verified_at = now
            await session.commit()
            await session.refresh(existing)
            logger.info(
                "license re-activated",
                extra={"event": "license.reactivated", "license_id": license_id},
            )
            return ActivationOutcome(
                activation=existing,
                payload=verified.payload,
                already_activated=True,
            )

        other_on_device = await repository.get_activation_by_device(
            session, device.fingerprint
        )
        if other_on_device is not None:
            raise DeviceAlreadyActivatedError()

        activation = Activation(
            license_id=license_id,
            token=verified.token,
            product=verified.payload.product,
            edition=verified.payload.edition,
            license_type=verified.payload.license_type,
            customer_name=verified.payload.customer_name,
            customer_email=(
                str(verified.payload.customer_email)
                if verified.payload.customer_email
                else None
            ),
            device_fingerprint=device.fingerprint,
            key_id=verified.key_id,
            features=list(verified.payload.features),
            issued_at=verified.payload.issued_at,
            activated_at=now,
            last_verified_at=now,
            status="active",
        )
        session.add(activation)
        try:
            await session.commit()
        except IntegrityError as exc:
            await session.rollback()
            if await repository.get_activation_by_license_id(session, license_id):
                raise LicenseAlreadyActivatedError() from exc
            raise DeviceAlreadyActivatedError() from exc

        await session.refresh(activation)
        logger.info(
            "license activated",
            extra={"event": "license.activated", "license_id": license_id},
        )
        return ActivationOutcome(
            activation=activation,
            payload=verified.payload,
            already_activated=False,
        )

    async def verify(
        self, session: AsyncSession, token: str, device: DeviceIdentity
    ) -> VerifiedLicense:
        verified = self.validator.verify(token, device.fingerprint)
        if await repository.is_license_revoked(
            session, verified.payload.license_id
        ):
            raise LicenseRevokedError()
        return verified

    async def status(
        self, session: AsyncSession, device: DeviceIdentity
    ) -> StatusOutcome:
        activation = await repository.get_activation_by_device(
            session, device.fingerprint
        )
        if activation is None:
            return StatusOutcome(
                activation=None,
                payload=None,
                valid=False,
                reason="NOT_ACTIVATED",
            )

        try:
            verified = self.validator.verify(activation.token, device.fingerprint)
            if verified.payload.license_id != activation.license_id:
                return StatusOutcome(
                    activation=activation,
                    payload=None,
                    valid=False,
                    reason="LICENSE_ID_MISMATCH",
                )
            if await repository.is_license_revoked(
                session, activation.license_id
            ):
                return StatusOutcome(
                    activation=activation,
                    payload=None,
                    valid=False,
                    reason="LICENSE_REVOKED",
                )
        except LicenseError as exc:
            return StatusOutcome(
                activation=activation,
                payload=None,
                valid=False,
                reason=exc.code,
            )

        activation.last_verified_at = utcnow()
        await session.commit()
        await session.refresh(activation)
        return StatusOutcome(
            activation=activation,
            payload=verified.payload,
            valid=True,
            reason=None,
        )


def _apply_payload(activation: Activation, verified: VerifiedLicense) -> None:
    payload = verified.payload
    activation.token = verified.token
    activation.product = payload.product
    activation.edition = payload.edition
    activation.license_type = payload.license_type
    activation.customer_name = payload.customer_name
    activation.customer_email = (
        str(payload.customer_email) if payload.customer_email else None
    )
    activation.key_id = verified.key_id
    activation.features = list(payload.features)
    activation.issued_at = payload.issued_at
    activation.status = "active"
