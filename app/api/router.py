from __future__ import annotations

from fastapi import APIRouter

from app.api.routes import activations, admin, admin_auth, license, meta

api_router = APIRouter()
api_router.include_router(meta.router)
api_router.include_router(activations.router)
api_router.include_router(license.router)
api_router.include_router(admin_auth.router)
api_router.include_router(admin.router)
