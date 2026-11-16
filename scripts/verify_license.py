#!/usr/bin/env python3
"""Verify a license token entirely offline.

This command can be run on an air-gapped machine. It never contacts a network
service and only needs the public key, the token, and (optionally) the expected
device fingerprint.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from _common import PROJECT_ROOT, bootstrap

bootstrap()

from app.config import Settings
from app.core.crypto import KeyRing
from app.core.exceptions import KeyRingError, LicenseError
from app.services.license_service import LicenseValidator
from app.services.revocation import RevocationListStore


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--token-file", type=Path)
    source.add_argument("--token", type=str)
    parser.add_argument(
        "--public-key-dir",
        type=Path,
        default=PROJECT_ROOT / "keys" / "public",
    )
    parser.add_argument("--public-key-file", type=Path, default=None)
    parser.add_argument("--public-key-b64", default=None)
    parser.add_argument(
        "--fingerprint",
        required=True,
        help="Full 64-character fingerprint shown by the PharmaPOS app.",
    )
    parser.add_argument("--product", default="PharmaPOS")
    parser.add_argument("--revocation-file", type=Path, default=None)
    args = parser.parse_args()

    token = (
        args.token
        if args.token is not None
        else args.token_file.read_text(encoding="utf-8")
    )

    try:
        keyring = KeyRing.load(
            directory=args.public_key_dir,
            file=args.public_key_file,
            public_key_b64=args.public_key_b64,
        )
        settings = Settings(
            environment="development",
            product=args.product,
            device_override=None,
            public_key_dir=args.public_key_dir,
            revocation_file=args.revocation_file,
            admin_enabled=False,
        )
        validator = LicenseValidator(
            settings,
            keyring,
            RevocationListStore(keyring, args.revocation_file),
        )
        verified = validator.verify(token, args.fingerprint)
    except KeyRingError as exc:
        print(json.dumps({"valid": False, "error": str(exc)}), file=sys.stderr)
        return 2
    except LicenseError as exc:
        print(
            json.dumps(
                {"valid": False, "code": exc.code, "error": str(exc)}
            ),
            file=sys.stderr,
        )
        return 1

    print(
        json.dumps(
            {
                "valid": True,
                "key_id": verified.key_id,
                "license": verified.payload.model_dump(mode="json"),
                "device_fingerprint": args.fingerprint,
            },
            indent=2,
            default=str,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
