"""Start the licensing service.

Usage:
    python run.py

Production deployments should use:
    uvicorn app.main:create_app --factory --host 127.0.0.1 --port 8765
"""

from __future__ import annotations

import uvicorn

from app.config import get_settings
from app.main import create_app


def main() -> None:
    settings = get_settings()
    uvicorn.run(
        create_app(settings),
        host=settings.host,
        port=settings.port,
        log_level=settings.log_level.lower(),
        log_config=None,
        access_log=False,
    )


if __name__ == "__main__":
    main()
