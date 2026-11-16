from __future__ import annotations

import hashlib
import hmac

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi import APIRouter, Depends
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.dependencies import (
    enforce_rate_limit,
    get_app_settings,
    get_license_service,
    get_session,
    get_signing_private_key,
)
from app.config import Settings
from app.core.device import DeviceIdentity, format_short_id
from app.core.exceptions import LicenseAlreadyActivatedError, LicenseError
from app.db import repository
from app.schemas.activation import (
    ActivationResponse,
    CustomerActivationRequest,
    LicenseTokenRequest,
)
from app.schemas.license import DeviceSummary, LicenseSummary
from app.services.issuer import create_license_token
from app.services.license_service import LicenseService

router = APIRouter(
    prefix="/activations",
    tags=["activations"],
    dependencies=[Depends(enforce_rate_limit)],
)


@router.post("", response_model=ActivationResponse)
async def activate(
    payload: LicenseTokenRequest,
    session: AsyncSession = Depends(get_session),
    service: LicenseService = Depends(get_license_service),
) -> ActivationResponse:
    device = DeviceIdentity(
        fingerprint=payload.device.fingerprint,
        short_id=format_short_id(payload.device.fingerprint),
        platform=payload.device.platform,
    )
    outcome = await service.activate(session, payload.license_key, device)
    return ActivationResponse(
        activation_id=outcome.activation.id,
        already_activated=outcome.already_activated,
        license=LicenseSummary.from_payload(outcome.payload),
        device=DeviceSummary(**device.public_dict()),
        activated_at=outcome.activation.activated_at,
        last_verified_at=outcome.activation.last_verified_at,
    )


@router.post("/claim", response_model=ActivationResponse)
async def activate_customer_license(
    payload: CustomerActivationRequest,
    session: AsyncSession = Depends(get_session),
    service: LicenseService = Depends(get_license_service),
    settings: Settings = Depends(get_app_settings),
    signing_key: Ed25519PrivateKey = Depends(get_signing_private_key),
) -> ActivationResponse:
    managed = await repository.get_customer_license(session, payload.username)
    presented_hash = hashlib.sha256(
        payload.license_code.encode("utf-8")
    ).hexdigest()
    if (
        managed is None
        or managed.status != "active"
        or not hmac.compare_digest(managed.activation_code_hash, presented_hash)
    ):
        raise LicenseError(
            "The username or license code is incorrect.",
            code="INVALID_CREDENTIALS",
            status_code=401,
        )

    if managed.device_fingerprint and not hmac.compare_digest(
        managed.device_fingerprint, payload.device.fingerprint
    ):
        raise LicenseAlreadyActivatedError()

    device = DeviceIdentity(
        fingerprint=payload.device.fingerprint,
        short_id=format_short_id(payload.device.fingerprint),
        platform=payload.device.platform,
    )
    token, signed_license = create_license_token(
        signing_key,
        device_fingerprint=device.fingerprint,
        customer_name=managed.customer_name,
        customer_email=managed.customer_email,
        product=settings.product,
        license_id=managed.license_id,
        metadata={"username": managed.username},
    )
    outcome = await service.activate(session, token, device)
    managed.device_fingerprint = device.fingerprint
    try:
        await session.commit()
    except IntegrityError as exc:
        await session.rollback()
        raise LicenseAlreadyActivatedError() from exc

    return ActivationResponse(
        license_key=token,
        activation_id=outcome.activation.id,
        already_activated=outcome.already_activated,
        license=LicenseSummary.from_payload(signed_license),
        device=DeviceSummary(**device.public_dict()),
        activated_at=outcome.activation.activated_at,
        last_verified_at=outcome.activation.last_verified_at,
    )
