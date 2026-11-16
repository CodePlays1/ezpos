from __future__ import annotations

import logging

from fastapi import APIRouter, Depends
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.concurrency import run_in_threadpool

from app.api.dependencies import get_app_settings, get_license_service, get_session
from app.config import Settings
from app.core.exceptions import LicenseError
from app.schemas.common import HealthResponse
from app.services.license_service import LicenseService

logger = logging.getLogger(__name__)

router = APIRouter(tags=["health"])


@router.get("/health/live", response_model=HealthResponse)
def live(settings: Settings = Depends(get_app_settings)) -> HealthResponse:
    return HealthResponse(
        status="ok", service=settings.app_name, version=settings.app_version
    )


@router.get("/health/ready", response_model=HealthResponse)
async def ready(
    settings: Settings = Depends(get_app_settings),
    session: AsyncSession = Depends(get_session),
    service: LicenseService = Depends(get_license_service),
) -> HealthResponse:
    try:
        await session.execute(text("SELECT 1"))
        if service.revocations.configured:
            await run_in_threadpool(service.revocations.verify_ready)
    except Exception as exc:
        logger.warning("readiness check failed: %s", exc)
        raise LicenseError(
            "The licensing service is not ready.",
            code="NOT_READY",
            status_code=503,
        ) from exc
    return HealthResponse(
        status="ready", service=settings.app_name, version=settings.app_version
    )
