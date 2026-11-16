from __future__ import annotations

from fastapi import APIRouter, Depends

from app.api.dependencies import get_app_settings, get_keyring
from app.config import Settings
from app.core.crypto import KeyRing
from app.schemas.common import VersionResponse

router = APIRouter(tags=["meta"])


@router.get("/version", response_model=VersionResponse)
def version(
    settings: Settings = Depends(get_app_settings),
    keyring: KeyRing = Depends(get_keyring),
) -> VersionResponse:
    return VersionResponse(
        service=settings.app_name,
        version=settings.app_version,
        product=settings.product,
        environment=settings.environment,
        key_ids=list(keyring.key_ids),
    )
