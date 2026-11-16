"""Domain exceptions mapped to structured HTTP errors."""

from __future__ import annotations

from typing import Any


class LicenseError(Exception):
    """Base class for all expected licensing failures."""

    code = "LICENSE_ERROR"
    status_code = 400
    default_message = "License validation failed."

    def __init__(
        self,
        message: str | None = None,
        *,
        code: str | None = None,
        status_code: int | None = None,
        details: Any = None,
    ) -> None:
        super().__init__(message or self.default_message)
        if code is not None:
            self.code = code
        if status_code is not None:
            self.status_code = status_code
        self.details = details
        self.retry_after: int | None = None


class TokenFormatError(LicenseError):
    code = "INVALID_TOKEN"
    status_code = 400
    default_message = "The license token is malformed."


class TokenSignatureError(LicenseError):
    code = "INVALID_SIGNATURE"
    status_code = 401
    default_message = "The license signature could not be verified."


class UnknownSigningKeyError(LicenseError):
    code = "UNKNOWN_SIGNING_KEY"
    status_code = 401
    default_message = "The license was signed with an unknown key."


class KeyRingError(RuntimeError):
    """Raised when verification keys cannot be loaded safely."""


class PrivateKeyPasswordRequired(ValueError):
    """Raised when an encrypted private key is loaded without a password."""


class LicensePayloadError(LicenseError):
    code = "INVALID_LICENSE_PAYLOAD"
    status_code = 400
    default_message = "The signed license payload is invalid."


class UnsupportedLicenseVersionError(LicenseError):
    code = "UNSUPPORTED_LICENSE_VERSION"
    status_code = 400
    default_message = "This license schema version is not supported."


class WrongProductError(LicenseError):
    code = "WRONG_PRODUCT"
    status_code = 403
    default_message = "This license was issued for a different product."


class DeviceMismatchError(LicenseError):
    code = "DEVICE_MISMATCH"
    status_code = 403
    default_message = "This license is bound to a different device."


class LicenseRevokedError(LicenseError):
    code = "LICENSE_REVOKED"
    status_code = 403
    default_message = "This license has been revoked."


class LicenseNotYetValidError(LicenseError):
    code = "LICENSE_NOT_YET_VALID"
    status_code = 403
    default_message = "This license is not valid yet."


class LicenseAlreadyActivatedError(LicenseError):
    code = "LICENSE_ALREADY_ACTIVATED"
    status_code = 409
    default_message = "This license is already activated on another device."


class DeviceAlreadyActivatedError(LicenseError):
    code = "DEVICE_ALREADY_ACTIVATED"
    status_code = 409
    default_message = "This device already has a different active license."


class LicenseNotActivatedError(LicenseError):
    code = "NOT_ACTIVATED"
    status_code = 404
    default_message = "No license has been activated on this device."


class DeviceIdentityError(RuntimeError):
    """Raised when a stable hardware fingerprint cannot be computed."""


class RevocationListError(LicenseError):
    code = "REVOCATION_LIST_UNAVAILABLE"
    status_code = 503
    default_message = "The signed revocation list could not be loaded."


class AdminDisabledError(LicenseError):
    code = "ADMIN_DISABLED"
    status_code = 404
    default_message = "The administrative API is disabled."


class AdminUnauthorizedError(LicenseError):
    code = "UNAUTHORIZED"
    status_code = 401
    default_message = "A valid administrative API key is required."


class RateLimitExceeded(LicenseError):
    code = "RATE_LIMITED"
    status_code = 429
    default_message = "Too many requests. Try again later."

    def __init__(self, retry_after: int, message: str | None = None) -> None:
        super().__init__(message)
        self.retry_after = max(1, int(retry_after))
