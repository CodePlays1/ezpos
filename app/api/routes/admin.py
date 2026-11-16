from __future__ import annotations

import hashlib
import secrets

from fastapi import APIRouter, Depends
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.dependencies import enforce_rate_limit, get_session, require_admin
from app.core.device import format_short_id
from app.core.exceptions import LicenseError, LicenseNotActivatedError
from app.db import repository
from app.db.models import CustomerLicense
from app.schemas.activation import (
    AdminActivationResponse,
    CreateCustomerLicenseRequest,
    CreatedCustomerLicenseResponse,
    CustomerLicenseResponse,
    DeactivateLicenseRequest,
    DeactivateLicenseResponse,
    RevokeLicenseRequest,
    RevokeLicenseResponse,
)
from app.services.issuer import generate_license_id

router = APIRouter(
    prefix="/admin",
    tags=["admin"],
    dependencies=[Depends(enforce_rate_limit), Depends(require_admin)],
)


def _new_activation_code() -> str:
    return f"EZP-{secrets.token_hex(24).upper()}"


@router.get("/activations", response_model=list[AdminActivationResponse])
async def list_activations(
    session: AsyncSession = Depends(get_session),
) -> list[AdminActivationResponse]:
    activations = await repository.list_activations(session)
    return [
        AdminActivationResponse(
            activation_id=activation.id,
            license_id=activation.license_id,
            product=activation.product,
            edition=activation.edition,
            license_type=activation.license_type,
            customer_name=activation.customer_name,
            customer_email=activation.customer_email,
            device_fingerprint=activation.device_fingerprint,
            device_short_id=format_short_id(activation.device_fingerprint),
            key_id=activation.key_id,
            features=list(activation.features or []),
            activated_at=activation.activated_at,
            last_verified_at=activation.last_verified_at,
            status=activation.status,
        )
        for activation in activations
    ]


@router.get("/licenses", response_model=list[CustomerLicenseResponse])
async def list_customer_licenses(
    session: AsyncSession = Depends(get_session),
) -> list[CustomerLicenseResponse]:
    licenses = await repository.list_customer_licenses(session)
    return [
        CustomerLicenseResponse(
            license_id=item.license_id,
            username=item.username,
            customer_name=item.customer_name,
            customer_email=item.customer_email,
            device_fingerprint=item.device_fingerprint,
            status=item.status,
            created_at=item.created_at,
        )
        for item in licenses
    ]


@router.post("/licenses", response_model=CreatedCustomerLicenseResponse)
async def create_customer_license(
    payload: CreateCustomerLicenseRequest,
    session: AsyncSession = Depends(get_session),
) -> CreatedCustomerLicenseResponse:
    activation_code = _new_activation_code()
    license = CustomerLicense(
        license_id=generate_license_id(prefix="EZ"),
        username=payload.username,
        activation_code_hash=hashlib.sha256(
            activation_code.encode("ascii")
        ).hexdigest(),
        customer_name=payload.customer_name,
        customer_email=payload.customer_email,
    )
    session.add(license)
    try:
        await session.commit()
    except IntegrityError as exc:
        await session.rollback()
        raise LicenseError(
            "A license account with this username already exists.",
            code="USERNAME_ALREADY_EXISTS",
            status_code=409,
        ) from exc
    await session.refresh(license)
    return CreatedCustomerLicenseResponse(
        license_id=license.license_id,
        username=license.username,
        customer_name=license.customer_name,
        customer_email=license.customer_email,
        device_fingerprint=license.device_fingerprint,
        status=license.status,
        created_at=license.created_at,
        activation_code=activation_code,
    )


@router.post(
    "/licenses/{license_id}/reset-code",
    response_model=CreatedCustomerLicenseResponse,
)
async def reset_customer_license_code(
    license_id: str,
    session: AsyncSession = Depends(get_session),
) -> CreatedCustomerLicenseResponse:
    license = await repository.get_customer_license_by_id(session, license_id)
    if license is None or license.status != "active":
        raise LicenseNotActivatedError("The customer license is not active.")
    activation_code = _new_activation_code()
    license.activation_code_hash = hashlib.sha256(
        activation_code.encode("ascii")
    ).hexdigest()
    await session.commit()
    await session.refresh(license)
    return CreatedCustomerLicenseResponse(
        license_id=license.license_id,
        username=license.username,
        customer_name=license.customer_name,
        customer_email=license.customer_email,
        device_fingerprint=license.device_fingerprint,
        status=license.status,
        created_at=license.created_at,
        activation_code=activation_code,
    )


@router.post("/licenses/{license_id}/revoke", response_model=RevokeLicenseResponse)
async def revoke_customer_license(
    license_id: str,
    payload: RevokeLicenseRequest,
    session: AsyncSession = Depends(get_session),
) -> RevokeLicenseResponse:
    if license_id != payload.license_id:
        raise LicenseError(
            "The license ID in the path and request must match.",
            code="LICENSE_ID_MISMATCH",
            status_code=422,
        )
    license = await repository.get_customer_license_by_id(session, license_id)
    if license is None:
        raise LicenseNotActivatedError("The customer license was not found.")
    revoked = await repository.revoke_license(session, license_id, payload.reason)
    return RevokeLicenseResponse(
        license_id=revoked.license_id,
        revoked=True,
        reason=revoked.reason,
        revoked_at=revoked.revoked_at,
    )


@router.post(
    "/licenses/{license_id}/deactivate",
    response_model=DeactivateLicenseResponse,
)
async def deactivate_customer_license(
    license_id: str,
    session: AsyncSession = Depends(get_session),
) -> DeactivateLicenseResponse:
    license = await repository.get_customer_license_by_id(session, license_id)
    if license is None or license.status != "active":
        raise LicenseNotActivatedError("The customer license is not active.")
    await repository.delete_activation_by_license_id(session, license_id)
    return DeactivateLicenseResponse(license_id=license_id, deactivated=True)


@router.post("/revoke", response_model=RevokeLicenseResponse)
async def revoke(
    payload: RevokeLicenseRequest,
    session: AsyncSession = Depends(get_session),
) -> RevokeLicenseResponse:
    revoked = await repository.revoke_license(
        session, payload.license_id, payload.reason
    )
    return RevokeLicenseResponse(
        license_id=revoked.license_id,
        revoked=True,
        reason=revoked.reason,
        revoked_at=revoked.revoked_at,
    )


@router.get("/revocations", response_model=list[RevokeLicenseResponse])
async def list_revocations(
    session: AsyncSession = Depends(get_session),
) -> list[RevokeLicenseResponse]:
    revocations = await repository.list_revocations(session)
    return [
        RevokeLicenseResponse(
            license_id=item.license_id,
            revoked=True,
            reason=item.reason,
            revoked_at=item.revoked_at,
        )
        for item in revocations
    ]


@router.post("/deactivate", response_model=DeactivateLicenseResponse)
async def deactivate(
    payload: DeactivateLicenseRequest,
    session: AsyncSession = Depends(get_session),
) -> DeactivateLicenseResponse:
    removed = await repository.delete_activation_by_license_id(
        session, payload.license_id
    )
    if not removed:
        raise LicenseNotActivatedError()
    return DeactivateLicenseResponse(
        license_id=payload.license_id, deactivated=True
    )
