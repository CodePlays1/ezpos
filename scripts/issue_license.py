#!/usr/bin/env python3
"""Issue a signed, lifetime, single-device license token."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from _common import PROJECT_ROOT, bootstrap, load_private_key_interactive, write_token_file

bootstrap()

from app.core.crypto import key_id_for_private_key
from app.core.exceptions import KeyRingError
from app.services.issuer import create_license_token


def _metadata(values: list[str]) -> dict[str, str]:
    result: dict[str, str] = {}
    for item in values:
        key, separator, value = item.partition("=")
        if not separator or not key.strip():
            raise argparse.ArgumentTypeError(
                f"Invalid metadata entry '{item}'. Use KEY=VALUE."
            )
        result[key.strip()] = value.strip()
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--private-key",
        type=Path,
        default=PROJECT_ROOT / "keys" / "private" / "license-signing-key.pem",
        help="Ed25519 private key PEM (vendor signing machine only).",
    )
    parser.add_argument(
        "--device-fingerprint",
        required=True,
        help="Full 64-character fingerprint obtained from the customer's app.",
    )
    parser.add_argument("--customer-name", required=True)
    parser.add_argument("--customer-email", default=None)
    parser.add_argument("--license-id", default=None)
    parser.add_argument("--product", default="PharmaPOS")
    parser.add_argument("--edition", default="standard")
    parser.add_argument(
        "--feature",
        action="append",
        default=[],
        help="Feature name to include in the signed license (repeatable).",
    )
    parser.add_argument(
        "--metadata",
        action="append",
        default=[],
        metavar="KEY=VALUE",
        help="Additional signed metadata (repeatable).",
    )
    parser.add_argument(
        "--out",
        type=Path,
        default=None,
        help="Write the token to this file instead of stdout.",
    )
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args()

    try:
        metadata = _metadata(args.metadata)
    except argparse.ArgumentTypeError as exc:
        parser.error(str(exc))

    try:
        private_key = load_private_key_interactive(args.private_key)
    except KeyRingError as exc:
        parser.error(str(exc))

    try:
        token, payload = create_license_token(
            private_key,
            device_fingerprint=args.device_fingerprint,
            customer_name=args.customer_name,
            customer_email=args.customer_email,
            product=args.product,
            license_id=args.license_id,
            edition=args.edition,
            features=args.feature,
            metadata=metadata,
        )
    except Exception as exc:
        parser.error(f"Unable to issue license: {exc}")

    if args.out is not None:
        write_token_file(args.out, token)

    if not args.quiet:
        summary = {
            "license_id": payload.license_id,
            "key_id": key_id_for_private_key(private_key),
            "product": payload.product,
            "edition": payload.edition,
            "license_type": payload.license_type,
            "device_limit": payload.device_limit,
            "customer": payload.customer_name,
            "device_fingerprint": payload.device_fingerprint,
            "issued_at": payload.issued_at.isoformat(),
            "features": payload.features,
        }
        print(json.dumps(summary, indent=2), file=sys.stderr)
        if args.out is not None:
            print(f"License token written to: {args.out}", file=sys.stderr)

    if args.out is None:
        print(token)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
