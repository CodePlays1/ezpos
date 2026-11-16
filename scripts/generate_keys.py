#!/usr/bin/env python3
"""Generate an Ed25519 keypair for license signing.

The private key stays on the vendor's signing workstation. Only the public key
is copied to customer installations.
"""

from __future__ import annotations

import argparse
import base64
import getpass
import os
import sys

from _common import PROJECT_ROOT, bootstrap

bootstrap()

from cryptography.hazmat.primitives import serialization

from app.core.crypto import (
    encode_private_key,
    encode_public_key,
    generate_keypair,
    key_id_for_private_key,
    write_file_atomic,
)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--out-dir",
        type=str,
        default=str(PROJECT_ROOT / "keys"),
        help="Key root directory (default: ./keys).",
    )
    parser.add_argument(
        "--name",
        default="license-signing-key",
        help="Private key filename without .pem (default: license-signing-key).",
    )
    parser.add_argument(
        "--electron-public-dir",
        type=str,
        default=str(PROJECT_ROOT.parent / "licensing" / "public"),
        help="Public-key directory bundled by Electron (default: ../licensing/public).",
    )
    parser.add_argument(
        "--encrypt",
        action="store_true",
        default=True,
        help="Encrypt the private key (default; retained for compatibility).",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Overwrite existing key files.",
    )
    args = parser.parse_args()

    password = os.environ.get("POS_LICENSE_SIGNING_KEY_PASSWORD")
    if password is None:
        password = os.environ.get("LICENSE_PRIVATE_KEY_PASSWORD")
    if password is None:
        if not sys.stdin.isatty():
            parser.error(
                "Choose a private-key password by setting "
                "POS_LICENSE_SIGNING_KEY_PASSWORD or "
                "LICENSE_PRIVATE_KEY_PASSWORD, or run this command interactively."
            )
        password = getpass.getpass("Choose private key password (12+ characters): ")
        confirm = getpass.getpass("Confirm private key password: ")
        if password != confirm:
            parser.error("Passwords do not match.")
    if len(password) < 12:
        parser.error("Use a password with at least 12 characters.")

    private_key, public_key = generate_keypair()
    key_id = key_id_for_private_key(private_key)

    out_dir = os.path.abspath(os.path.expanduser(args.out_dir))
    private_path = os.path.join(out_dir, "private", f"{args.name}.pem")
    public_path = os.path.join(out_dir, "public", f"{key_id}.pem")
    electron_public_path = os.path.join(
        os.path.abspath(os.path.expanduser(args.electron_public_dir)),
        f"{key_id}.pem",
    )

    if not args.force and (
        os.path.exists(private_path)
        or os.path.exists(public_path)
        or os.path.exists(electron_public_path)
    ):
        parser.error(
            "Key files already exist. Use --force to replace them or choose a "
            "different --name."
        )

    private_pem = encode_private_key(private_key, password=password)
    public_pem = encode_public_key(public_key)
    raw_public = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )

    from pathlib import Path

    write_file_atomic(Path(private_path), private_pem, mode=0o600)
    write_file_atomic(Path(public_path), public_pem, mode=0o644)
    write_file_atomic(Path(electron_public_path), public_pem, mode=0o644)

    print(f"Key ID: {key_id}")
    print(f"Private key: {private_path}")
    print(f"Public key: {public_path}")
    print(f"Electron public key: {electron_public_path}")
    print(f"Public key (base64): {base64.b64encode(raw_public).decode('ascii')}")
    print(
        "WARNING: never ship the private key with the POS application.",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
