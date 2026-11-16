"""FastAPI dependencies."""

from __future__ import annotations

import base64
import hmac
from collections.abc import AsyncIterator
from typing import Annotated

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi import Depends, Header, Request
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import Settings
from app.core.admin_auth import verify_admin_password
from app.core.crypto import KeyRing
from app.core.exceptions import (
    AdminDisabledError,
    AdminUnauthorizedError,
    LicenseError,
)
from app.db import repository
from app.services.license_service import LicenseService


async def get_session(request: Request) -> AsyncIterator[AsyncSession]:
    session_factory = request.app.state.session_factory
    async with session_factory() as session:
        yield session


def get_app_settings(request: Request) -> Settings:
    return request.app.state.settings


def get_keyring(request: Request) -> KeyRing:
    return request.app.state.keyring


def get_license_service(request: Request) -> LicenseService:
    return request.app.state.license_service


def get_signing_private_key(request: Request) -> Ed25519PrivateKey:
    signing_key = request.app.state.signing_private_key
    if signing_key is None:
        raise LicenseError(
            "The license signing service is not configured.",
            code="SIGNING_UNAVAILABLE",
            status_code=503,
        )
    return signing_key


async def enforce_rate_limit(request: Request) -> None:
    limiter = request.app.state.rate_limiter
    await limiter.check(request)


async def require_admin(
    request: Request,
    x_admin_key: Annotated[str | None, Header(alias="X-Admin-Key")] = None,
    authorization: Annotated[str | None, Header()] = None,
    session: AsyncSession = Depends(get_session),
) -> None:
    settings: Settings = request.app.state.settings
    if (
        settings.admin_enabled
        and settings.admin_api_key
        and x_admin_key
        and hmac.compare_digest(
            x_admin_key.encode("utf-8"), settings.admin_api_key.encode("utf-8")
        )
    ):
        return

    account = await repository.get_admin_account(session)
    if account is None:
        if not settings.admin_enabled:
            raise AdminDisabledError()
        raise AdminUnauthorizedError()

    if not authorization or not authorization.startswith("Basic "):
        raise AdminUnauthorizedError()
    try:
        decoded = base64.b64decode(authorization[6:], validate=True).decode("utf-8")
        username, password = decoded.split(":", 1)
    except (ValueError, UnicodeDecodeError):
        raise AdminUnauthorizedError() from None
    if (
        not hmac.compare_digest(username.casefold(), account.username)
        or not verify_admin_password(
            password, account.password_salt, account.password_hash
        )
    ):
        raise AdminUnauthorizedError()
