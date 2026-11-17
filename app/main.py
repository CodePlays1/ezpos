"""FastAPI application factory."""

from __future__ import annotations

import logging
import os
import secrets
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.concurrency import run_in_threadpool
from starlette.middleware.trustedhost import TrustedHostMiddleware

from app.api.errors import register_exception_handlers
from app.api.middleware import RequestContextMiddleware
from app.api.router import api_router
from app.api.routes.health import router as health_router
from app.config import Settings, get_settings
from app.core.crypto import (
    KeyRing,
    key_id_for_private_key,
    load_private_key_b64,
)
from app.core.exceptions import KeyRingError
from app.core.rate_limit import RateLimiter
from app.db import repository
from app.db.session import create_engine_and_session, create_schema
from app.logging_config import configure_logging
from app.services.license_service import LicenseService

logger = logging.getLogger(__name__)


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or get_settings()
    configure_logging(settings)

    if settings.environment == "production":
        if not settings.public_key_b64:
            raise KeyRingError(
                "POS_LICENSE_PUBLIC_KEY_B64 is required in production; "
                "production does not load public keys from files."
            )
        keyring = KeyRing.load(public_key_b64=settings.public_key_b64)
        if not settings.signing_private_key_b64:
            raise KeyRingError(
                "POS_LICENSE_SIGNING_PRIVATE_KEY_B64 is required in production."
            )
        if not settings.signing_key_password:
            raise KeyRingError(
                "POS_LICENSE_SIGNING_KEY_PASSWORD is required in production."
            )
    else:
        keyring = KeyRing.load(
            directory=settings.public_key_dir,
            file=settings.public_key_file,
            public_key_b64=settings.public_key_b64,
        )
    signing_private_key = None
    if settings.signing_private_key_b64 and settings.signing_key_password:
        signing_private_key = load_private_key_b64(
            settings.signing_private_key_b64,
            password=settings.signing_key_password or "",
        )
        if key_id_for_private_key(signing_private_key) not in keyring.key_ids:
            raise KeyRingError(
                "The configured license signing key has no matching public key."
            )
    engine, session_factory = create_engine_and_session(settings)
    license_service = LicenseService(settings, keyring)
    rate_limiter = RateLimiter(settings.rate_limit_per_minute)
    setup_token = secrets.token_urlsafe(32)

    @asynccontextmanager
    async def lifespan(_app: FastAPI):
        await create_schema(engine)
        await run_in_threadpool(license_service.revocations.verify_ready)
        async with session_factory() as session:
            admin_account = await repository.get_admin_account(session)
        if admin_account is None and not (
            settings.admin_enabled and settings.admin_api_key
        ):
            logger.warning(
                "Dashboard first-run setup code: %s",
                setup_token,
                extra={"event": "admin.setup_required"},
            )
        logger.info(
            "licensing service started",
            extra={
                "event": "app.startup",
                "product": settings.product,
                "key_ids": list(keyring.key_ids),
                "environment": settings.environment,
            },
        )
        try:
            yield
        finally:
            await engine.dispose()
            logger.info("licensing service stopped", extra={"event": "app.shutdown"})

    app = FastAPI(
        title=settings.app_name,
        version=settings.app_version,
        description=(
            "Offline, device-bound lifetime license activation and verification "
            "using Ed25519 signatures."
        ),
        docs_url="/docs" if settings.docs_enabled else None,
        redoc_url=None,
        openapi_url="/openapi.json" if settings.docs_enabled else None,
        lifespan=lifespan,
    )

    app.state.settings = settings
    app.state.keyring = keyring
    app.state.engine = engine
    app.state.session_factory = session_factory
    app.state.license_service = license_service
    app.state.signing_private_key = signing_private_key
    app.state.rate_limiter = rate_limiter
    app.state.setup_token = setup_token

    app.add_middleware(RequestContextMiddleware)
    allowed_hosts = set(settings.allowed_hosts)
    render_hostname = os.environ.get("RENDER_EXTERNAL_HOSTNAME")
    if render_hostname:
        allowed_hosts.add(render_hostname)
    app.add_middleware(
        TrustedHostMiddleware, allowed_hosts=sorted(allowed_hosts)
    )

    if settings.cors_origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=list(settings.cors_origins),
            allow_credentials=False,
            allow_methods=["GET", "POST"],
            allow_headers=["Content-Type", "X-Admin-Key", "X-Request-ID"],
            max_age=600,
        )

    register_exception_handlers(app)

    app.include_router(health_router)
    app.include_router(api_router, prefix=settings.api_prefix)
    admin_assets = Path(__file__).parent / "static" / "admin"
    admin_templates = Jinja2Templates(directory=Path(__file__).parent / "templates")
    app.mount(
        "/admin-assets",
        StaticFiles(directory=admin_assets),
        name="admin-assets",
    )

    @app.get("/admin", include_in_schema=False)
    def admin_dashboard(request: Request):
        response = admin_templates.TemplateResponse(
            request=request,
            name="admin.html",
            context={"request": request, "product_name": "EZ POS"},
        )
        response.headers.update(
            {
                "Cache-Control": "no-store",
                "Content-Security-Policy": (
                    "default-src 'self'; script-src 'self'; style-src 'self'; "
                    "connect-src 'self'; object-src 'none'; base-uri 'none'; "
                    "frame-ancestors 'none'; form-action 'self'"
                ),
                "Referrer-Policy": "no-referrer",
                "X-Content-Type-Options": "nosniff",
            }
        )
        return response

    @app.get("/", include_in_schema=False)
    def root() -> dict[str, str | None]:
        return {
            "service": settings.app_name,
            "version": settings.app_version,
            "product": settings.product,
            "docs": "/docs" if settings.docs_enabled else None,
            "health": "/health/ready",
        }

    return app
