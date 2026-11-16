"""Structured JSON error handling."""

from __future__ import annotations

import logging
from typing import Any

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.core.context import get_request_id
from app.core.exceptions import LicenseError

logger = logging.getLogger(__name__)


def register_exception_handlers(app: FastAPI) -> None:
    @app.exception_handler(LicenseError)
    async def _license_error_handler(
        _request: Request, exc: LicenseError
    ) -> JSONResponse:
        headers = {"Cache-Control": "no-store"}
        if exc.retry_after is not None:
            headers["Retry-After"] = str(exc.retry_after)
        return _error_response(
            status_code=exc.status_code,
            code=exc.code,
            message=str(exc),
            details=exc.details,
            headers=headers,
        )

    @app.exception_handler(RequestValidationError)
    async def _validation_error_handler(
        _request: Request, exc: RequestValidationError
    ) -> JSONResponse:
        details = [
            {
                "field": ".".join(str(part) for part in error.get("loc", ())),
                "message": error.get("msg", "Invalid value."),
                "type": error.get("type", "value_error"),
            }
            for error in exc.errors()
        ]
        return _error_response(
            status_code=422,
            code="VALIDATION_ERROR",
            message="The request body or parameters are invalid.",
            details=details,
        )

    @app.exception_handler(StarletteHTTPException)
    async def _http_error_handler(
        _request: Request, exc: StarletteHTTPException
    ) -> JSONResponse:
        if isinstance(exc.detail, str):
            message = exc.detail
        else:
            message = "The request could not be completed."
        return _error_response(
            status_code=exc.status_code,
            code=f"HTTP_{exc.status_code}",
            message=message,
        )

    @app.exception_handler(Exception)
    async def _unhandled_error_handler(
        _request: Request, exc: Exception
    ) -> JSONResponse:
        logger.exception("unhandled exception", exc_info=exc)
        return _error_response(
            status_code=500,
            code="INTERNAL_ERROR",
            message="An internal error occurred.",
        )


def _error_response(
    *,
    status_code: int,
    code: str,
    message: str,
    details: Any = None,
    headers: dict[str, str] | None = None,
) -> JSONResponse:
    return JSONResponse(
        status_code=status_code,
        content={
            "error": {
                "code": code,
                "message": message,
                "request_id": get_request_id(),
                "details": details,
            }
        },
        headers=headers or {"Cache-Control": "no-store"},
    )
