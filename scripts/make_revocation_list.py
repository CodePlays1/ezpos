#!/usr/bin/env python3
"""Create a signed offline revocation list for distribution."""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime
from pathlib import Path

from _common import PROJECT_ROOT, bootstrap, load_private_key_interactive, write_token_file

bootstrap()

from app.core.crypto import key_id_for_private_key
from app.core.exceptions import KeyRingError
from app.services.issuer import create_revocation_token
from app.services.revocation import RevocationEntry


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--private-key",
        type=Path,
        default=PROJECT_ROOT / "keys" / "private" / "license-signing-key.pem",
    )
    parser.add_argument(
        "--revoke",
        action="append",
        required=True,
        metavar="LICENSE_ID",
        help="License ID to revoke (repeatable).",
    )
    parser.add_argument("--reason", default="")
    parser.add_argument(
        "--out",
        type=Path,
        default=PROJECT_ROOT / "revocation.token",
    )
    args = parser.parse_args()

    try:
        private_key = load_private_key_interactive(args.private_key)
    except KeyRingError as exc:
        parser.error(str(exc))

    revoked_at = datetime.now().astimezone()
    entries = [
        RevocationEntry(
            license_id=license_id, reason=args.reason, revoked_at=revoked_at
        )
        for license_id in dict.fromkeys(args.revoke)
    ]

    try:
        token, document = create_revocation_token(private_key, entries)
    except Exception as exc:
        parser.error(f"Unable to create revocation list: {exc}")

    write_token_file(args.out, token)
    print(
        json.dumps(
            {
                "key_id": key_id_for_private_key(private_key),
                "revoked": [entry.license_id for entry in document.revoked],
                "out": str(args.out),
            },
            indent=2,
        ),
        file=sys.stderr,
    )
    print(f"Signed revocation list written to: {args.out}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
