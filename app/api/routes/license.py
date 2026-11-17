from __future__ import annotations

import math
from datetime import timedelta
from typing import Annotated

from fastapi import APIRouter, Depends, Query
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.dependencies import (
    enforce_rate_limit,
    get_license_service,
    get_session,
)
from app.core.device import DeviceIdentity, format_short_id
from app.core.time import utcnow
from app.db import repository
from app.db.models import TrialRegistration
from app.schemas.activation import ClientDevice, LicenseTokenRequest
from app.schemas.license import (
    DeviceSummary,
    LicenseRecoveryResponse,
    LicenseStatusResponse,
    LicenseSummary,
    LicenseVerifyResponse,
    TrialStatusResponse,
)
from app.services.license_service import LicenseService

router = APIRouter(
    prefix="/license",
    tags=["license"],
    dependencies=[Depends(enforce_rate_limit)],
)
TRIAL_DURATION = timedelta(days=7)


@router.post("/recover", response_model=LicenseRecoveryResponse)
async def recover_activation(
    payload: ClientDevice,
    session: AsyncSession = Depends(get_session),
    service: LicenseService = Depends(get_license_service),
) -> LicenseRecoveryResponse:
    device = DeviceIdentity(
        fingerprint=payload.fingerprint,
        short_id=format_short_id(payload.fingerprint),
        platform=payload.platform,
    )
    outcome = await service.status(session, device)
    activation = outcome.activation
    return LicenseRecoveryResponse(
        activated=activation is not None,
        valid=outcome.valid,
        reason=outcome.reason,
        license_key=activation.token if outcome.valid and activation else None,
        device=DeviceSummary(**device.public_dict()),
        checked_at=utcnow(),
    )


@router.post("/trial/status", response_model=TrialStatusResponse)
async def trial_status(
    payload: ClientDevice,
    session: AsyncSession = Depends(get_session),
) -> TrialStatusResponse:
    device = DeviceIdentity(
        fingerprint=payload.fingerprint,
        short_id=format_short_id(payload.fingerprint),
        platform=payload.platform,
    )
    existing_activation = await repository.get_activation_by_device(
        session, device.fingerprint
    )
    if existing_activation is not None:
        return TrialStatusResponse(
            valid=False,
            trial_days_remaining=0,
            reason="LICENSE_ACTIVATED",
            device=DeviceSummary(**device.public_dict()),
        )

    registration = await session.get(
        TrialRegistration, device.fingerprint
    )
    if registration is None:
        now = utcnow()
        registration = TrialRegistration(
            device_fingerprint=device.fingerprint,
            platform=device.platform,
            started_at=now,
            last_seen_at=now,
        )
        session.add(registration)
        try:
            await session.commit()
        except IntegrityError:
            await session.rollback()
            registration = await session.get(
                TrialRegistration, device.fingerprint
            )
            if registration is None:
                raise
    else:
        registration.last_seen_at = utcnow()
        await session.commit()

    now = utcnow()
    trial_ends_at = registration.started_at + TRIAL_DURATION
    remaining = max(
        0, math.ceil((trial_ends_at - now).total_seconds() / 86400)
    )
    valid = now < trial_ends_at
    return TrialStatusResponse(
        valid=valid,
        trial_days_remaining=remaining,
        trial_ends_at=trial_ends_at,
        reason="TRIAL_ACTIVE" if valid else "TRIAL_EXPIRED",
        device=DeviceSummary(**device.public_dict()),
    )


@router.get("/status", response_model=LicenseStatusResponse)
async def status(
    fingerprint: Annotated[str, Query(pattern=r"^[a-f0-9]{64}$")],
    platform: Annotated[str, Query(min_length=1, max_length=32)],
    session: AsyncSession = Depends(get_session),
    service: LicenseService = Depends(get_license_service),
) -> LicenseStatusResponse:
    device = DeviceIdentity(
        fingerprint=fingerprint,
        short_id=format_short_id(fingerprint),
        platform=platform,
    )
    outcome = await service.status(session, device)
    activation = outcome.activation
    return LicenseStatusResponse(
        activated=activation is not None,
        valid=outcome.valid,
        reason=outcome.reason,
        license=(
            LicenseSummary.from_payload(outcome.payload)
            if outcome.payload is not None
            else None
        ),
        device=DeviceSummary(**device.public_dict()),
        activation_id=activation.id if activation is not None else None,
        activated_at=activation.activated_at if activation is not None else None,
        last_verified_at=(
            activation.last_verified_at if activation is not None else None
        ),
        checked_at=utcnow(),
    )


@router.post("/verify", response_model=LicenseVerifyResponse)
async def verify(
    payload: LicenseTokenRequest,
    session: AsyncSession = Depends(get_session),
    service: LicenseService = Depends(get_license_service),
) -> LicenseVerifyResponse:
    device = DeviceIdentity(
        fingerprint=payload.device.fingerprint,
        short_id=format_short_id(payload.device.fingerprint),
        platform=payload.device.platform,
    )
    verified = await service.verify(session, payload.license_key, device)
    return LicenseVerifyResponse(
        license=LicenseSummary.from_payload(verified.payload),
        device=DeviceSummary(**device.public_dict()),
        key_id=verified.key_id,
        checked_at=utcnow(),
    )
