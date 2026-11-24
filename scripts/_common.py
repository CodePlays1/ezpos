"""Shared helpers for the offline signing CLI scripts."""

from __future__ import annotations

import getpass
import os
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent


def bootstrap() -> Path:
    root = str(PROJECT_ROOT)
    if root not in sys.path:
        sys.path.insert(0, root)
    return PROJECT_ROOT


def load_private_key_interactive(private_key_path: Path):
    from app.core.crypto import load_private_key
    from app.core.exceptions import KeyRingError, PrivateKeyPasswordRequired

    password = os.environ.get("LICENSE_PRIVATE_KEY_PASSWORD")
    try:
        return load_private_key(private_key_path, password=password)
    except PrivateKeyPasswordRequired:
        if not sys.stdin.isatty():
            raise SystemExit(
                "The private key is encrypted. Set LICENSE_PRIVATE_KEY_PASSWORD "
                "or run this command interactively."
            ) from None
        entered = getpass.getpass("Private key password: ")
        try:
            return load_private_key(private_key_path, password=entered)
        except KeyRingError as exc:
            raise SystemExit(str(exc)) from exc


def write_token_file(path: Path, token: str) -> None:
    from app.core.crypto import write_file_atomic

    write_file_atomic(path, f"{token}\n".encode(), mode=0o644)


def private_key_password_from_environment() -> str | None:
    value = os.environ.get("LICENSE_PRIVATE_KEY_PASSWORD")
    return value if value else None
