from __future__ import annotations

import hashlib
import secrets
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi import APIRouter, Depends
from fastapi.encoders import jsonable_encoder
from fastapi.responses import Response
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.dependencies import (
    enforce_rate_limit,
    get_keyring,
    get_session,
    get_signing_private_key,
    require_admin,
)
from app.core.crypto import (
    KeyRing,
    b64url_decode,
    b64url_encode,
    canonical_json,
    key_id_for_private_key,
)
from app.core.device import format_short_id
from app.core.exceptions import LicenseError, LicenseNotActivatedError
from app.core.time import utcnow
from app.db import repository
from app.db.models import (
    Activation,
    CustomerLicense,
    RevokedLicense,
    TrialRegistration,
)
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
from app.schemas.admin import (
    LicenseBackup,
    LicenseBackupData,
    LicenseBackupImportResponse,
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


@router.get("/backup", response_class=Response)
async def download_backup(
    signing_key: Ed25519PrivateKey = Depends(get_signing_private_key),
    session: AsyncSession = Depends(get_session),
) -> Response:
    models = {
        "activations": Activation,
        "customer_licenses": CustomerLicense,
        "trial_registrations": TrialRegistration,
        "revoked_licenses": RevokedLicense,
    }
    data: dict[str, list[dict[str, Any]]] = {}
    for name, model in models.items():
        records = await session.scalars(select(model))
        data[name] = [
            {
                column.name: getattr(record, column.name)
                for column in model.__table__.columns
            }
            for record in records
        ]

    data = jsonable_encoder(data)
    unsigned = LicenseBackup(
        format="ezpos-license-backup",
        version=1,
        key_id=key_id_for_private_key(signing_key),
        created_at=utcnow(),
        data=LicenseBackupData.model_validate(data),
        signature="A" * 86,
    ).model_dump(mode="json", exclude={"signature"})
    backup = {
        **unsigned,
        "signature": b64url_encode(signing_key.sign(canonical_json(unsigned))),
    }
    return Response(
        content=canonical_json(backup),
        media_type="application/json",
        headers={
            "Content-Disposition": 'attachment; filename="ezpos-license-backup.json"',
            "Cache-Control": "no-store",
            "X-Content-Type-Options": "nosniff",
        },
    )


@router.post("/backup", response_model=LicenseBackupImportResponse)
async def restore_backup(
    backup: LicenseBackup,
    keyring: KeyRing = Depends(get_keyring),
    session: AsyncSession = Depends(get_session),
) -> LicenseBackupImportResponse:
    if len(canonical_json(backup.model_dump(mode="json"))) > 10 * 1024 * 1024:
        raise LicenseError(
            "The backup file exceeds the 10 MB limit.",
            code="BACKUP_TOO_LARGE",
            status_code=413,
        )

    unsigned = backup.model_dump(mode="json", exclude={"signature"})
    public_key = keyring.get(backup.key_id)
    if public_key is None:
        raise LicenseError(
            "The backup was signed by a key this service does not trust.",
            code="BACKUP_KEY_UNTRUSTED",
            status_code=422,
        )
    try:
        public_key.verify(
            b64url_decode(backup.signature), canonical_json(unsigned)
        )
    except (InvalidSignature, LicenseError, ValueError):
        raise LicenseError(
            "The backup signature is invalid; the file may have been modified.",
            code="BACKUP_SIGNATURE_INVALID",
            status_code=422,
        ) from None

    existing_customers = list(
        (await session.scalars(select(CustomerLicense))).all()
    )
    existing_activations = list((await session.scalars(select(Activation))).all())
    existing_trials = list(
        (await session.scalars(select(TrialRegistration))).all()
    )
    existing_revocations = list(
        (await session.scalars(select(RevokedLicense))).all()
    )

    customer_ids = {row.license_id for row in existing_customers}
    usernames = {row.username.casefold() for row in existing_customers}
    customer_devices = {
        row.device_fingerprint
        for row in existing_customers
        if row.device_fingerprint is not None
    }
    activation_ids = {row.id for row in existing_activations}
    activation_licenses = {row.license_id for row in existing_activations}
    activation_devices = {row.device_fingerprint for row in existing_activations}
    trials = {row.device_fingerprint: row for row in existing_trials}
    revocations = {row.license_id: row for row in existing_revocations}

    restored = {
        "activations": 0,
        "customer_licenses": 0,
        "trial_registrations": 0,
        "revoked_licenses": 0,
    }
    customers_by_license = {
        row.license_id: row for row in existing_customers
    }

    for record in backup.data.customer_licenses:
        values = record.model_dump()
        username = values["username"].casefold()
        fingerprint = values["device_fingerprint"]
        if (
            values["license_id"] in customer_ids
            or username in usernames
            or (fingerprint is not None and fingerprint in customer_devices)
        ):
            continue
        customer = CustomerLicense(**values)
        session.add(customer)
        customer_ids.add(values["license_id"])
        customers_by_license[values["license_id"]] = customer
        usernames.add(username)
        if fingerprint is not None:
            customer_devices.add(fingerprint)
        restored["customer_licenses"] += 1

    for record in backup.data.activations:
        values = record.model_dump()
        if (
            values["id"] in activation_ids
            or values["license_id"] in activation_licenses
            or values["device_fingerprint"] in activation_devices
        ):
            continue
        session.add(Activation(**values))
        activation_ids.add(values["id"])
        activation_licenses.add(values["license_id"])
        activation_devices.add(values["device_fingerprint"])
        restored["activations"] += 1

    for record in backup.data.trial_registrations:
        values = record.model_dump()
        existing = trials.get(values["device_fingerprint"])
        if existing is None:
            existing = TrialRegistration(**values)
            session.add(existing)
            trials[values["device_fingerprint"]] = existing
            restored["trial_registrations"] += 1
        else:
            existing.started_at = min(existing.started_at, values["started_at"])
            existing.last_seen_at = max(existing.last_seen_at, values["last_seen_at"])

    for record in backup.data.revoked_licenses:
        values = record.model_dump()
        if values["license_id"] not in revocations:
            session.add(RevokedLicense(**values))
            revocations[values["license_id"]] = True
            restored["revoked_licenses"] += 1
        customer = customers_by_license.get(values["license_id"])
        if customer is not None:
            customer.status = "revoked"

    try:
        await session.commit()
    except IntegrityError as exc:
        await session.rollback()
        raise LicenseError(
            "The backup conflicts with existing license records. No backup data "
            "was restored.",
            code="BACKUP_CONFLICT",
            status_code=409,
        ) from exc

    return LicenseBackupImportResponse(restored=restored)


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
