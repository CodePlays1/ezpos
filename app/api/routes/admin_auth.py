from __future__ import annotations

import hmac

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi import APIRouter, Depends, Request
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.dependencies import enforce_rate_limit, get_session, require_admin
from app.core.admin_auth import hash_admin_password
from app.core.crypto import (
    key_id_for_private_key,
    load_configured_private_key,
)
from app.core.exceptions import AdminUnauthorizedError, KeyRingError, LicenseError
from app.db import repository
from app.db.models import AdminAccount
from app.schemas.admin import AdminSetupRequest, AdminUnlockRequest

router = APIRouter(prefix="/admin", tags=["admin setup"])


def _is_local_request(request: Request) -> bool:
    host = request.client.host if request.client else ""
    return host in {"127.0.0.1", "::1", "localhost", "testclient", "testserver"}


def _load_signing_key(
    request: Request, password: str | None = None
) -> Ed25519PrivateKey:
    settings = request.app.state.settings
    try:
        if settings.environment == "production":
            private_key = load_configured_private_key(
                b64_value=settings.signing_private_key_b64,
                file=settings.signing_private_key_file,
                password=settings.signing_key_password,
            )
        else:
            private_key = load_configured_private_key(
                b64_value=settings.signing_private_key_b64,
                file=settings.signing_private_key_file,
                password=password or settings.signing_key_password,
            )
    except (KeyRingError, ValueError) as exc:
        raise LicenseError(
            "The signing key could not be unlocked. Check its password and "
            "server key configuration.",
            code="SIGNING_KEY_UNLOCK_FAILED",
            status_code=400,
        ) from exc

    if key_id_for_private_key(private_key) not in request.app.state.keyring.key_ids:
        raise LicenseError(
            "The signing private key does not match the configured public key.",
            code="SIGNING_KEY_MISMATCH",
            status_code=400,
        )
    return private_key


@router.get("/setup-status")
async def setup_status(
    request: Request,
    session: AsyncSession = Depends(get_session),
) -> dict[str, object]:
    account = await repository.get_admin_account(session)
    settings = request.app.state.settings
    if settings.admin_enabled and settings.admin_api_key and account is None:
        return {
            "setup_required": False,
            "legacy_admin": True,
            "signing_ready": request.app.state.signing_private_key is not None,
        }

    result: dict[str, object] = {
        "setup_required": account is None,
        "legacy_admin": False,
        "signing_ready": request.app.state.signing_private_key is not None,
    }
    if account is None and _is_local_request(request):
        result["setup_token"] = request.app.state.setup_token
    return result


@router.post("/setup", dependencies=[Depends(enforce_rate_limit)])
async def setup_admin(
    payload: AdminSetupRequest,
    request: Request,
    session: AsyncSession = Depends(get_session),
) -> dict[str, str | bool]:
    if await repository.get_admin_account(session) is not None:
        raise LicenseError(
            "The dashboard administrator has already been created.",
            code="ADMIN_ALREADY_CONFIGURED",
            status_code=409,
        )
    expected = request.app.state.setup_token
    if not expected or not hmac.compare_digest(payload.setup_token, expected):
        raise AdminUnauthorizedError()

    signing_key = _load_signing_key(request, payload.signing_key_password)
    salt, password_hash = hash_admin_password(payload.password)
    account = AdminAccount(
        id="primary",
        username=payload.username.casefold(),
        password_salt=salt,
        password_hash=password_hash,
    )
    session.add(account)
    try:
        await session.commit()
    except IntegrityError as exc:
        await session.rollback()
        raise LicenseError(
            "The dashboard administrator has already been created.",
            code="ADMIN_ALREADY_CONFIGURED",
            status_code=409,
        ) from exc
    request.app.state.signing_private_key = signing_key
    request.app.state.setup_token = None
    return {"username": account.username, "signing_ready": True}


@router.post(
    "/unlock",
    dependencies=[Depends(require_admin), Depends(enforce_rate_limit)],
)
async def unlock_signing_key(
    payload: AdminUnlockRequest, request: Request
) -> dict[str, bool]:
    request.app.state.signing_private_key = _load_signing_key(
        request, payload.signing_key_password
    )
    return {"signing_ready": True}
