from __future__ import annotations

from datetime import datetime
from uuid import uuid4

from sqlalchemy import JSON, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.core.time import utcnow
from app.db.base import Base
from app.db.types import UTCDateTime


class Activation(Base):
    """A locally persisted, device-bound license activation."""

    __tablename__ = "activations"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid4())
    )
    license_id: Mapped[str] = mapped_column(
        String(64), unique=True, index=True, nullable=False
    )
    token: Mapped[str] = mapped_column(Text, nullable=False)
    product: Mapped[str] = mapped_column(String(64), nullable=False)
    edition: Mapped[str] = mapped_column(String(64), nullable=False)
    license_type: Mapped[str] = mapped_column(String(32), nullable=False)
    customer_name: Mapped[str] = mapped_column(String(255), nullable=False)
    customer_email: Mapped[str | None] = mapped_column(String(320), nullable=True)
    device_fingerprint: Mapped[str] = mapped_column(
        String(64), unique=True, index=True, nullable=False
    )
    key_id: Mapped[str] = mapped_column(String(64), nullable=False)
    features: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    issued_at: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False)
    activated_at: Mapped[datetime] = mapped_column(
        UTCDateTime(), default=utcnow, nullable=False
    )
    last_verified_at: Mapped[datetime] = mapped_column(
        UTCDateTime(), default=utcnow, nullable=False
    )
    status: Mapped[str] = mapped_column(
        String(16), default="active", index=True, nullable=False
    )
    created_at: Mapped[datetime] = mapped_column(
        UTCDateTime(), default=utcnow, nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        UTCDateTime(), default=utcnow, onupdate=utcnow, nullable=False
    )


class RevokedLicense(Base):
    """A locally recorded revocation for this installation."""

    __tablename__ = "revoked_licenses"

    license_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    reason: Mapped[str] = mapped_column(String(500), default="", nullable=False)
    revoked_at: Mapped[datetime] = mapped_column(
        UTCDateTime(), default=utcnow, nullable=False
    )


class CustomerLicense(Base):
    """Admin-managed customer login and one-time activation credential."""

    __tablename__ = "customer_licenses"

    license_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    username: Mapped[str] = mapped_column(
        String(60), unique=True, index=True, nullable=False
    )
    activation_code_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    customer_name: Mapped[str] = mapped_column(String(255), nullable=False)
    customer_email: Mapped[str | None] = mapped_column(String(320), nullable=True)
    device_fingerprint: Mapped[str | None] = mapped_column(
        String(64), unique=True, nullable=True
    )
    status: Mapped[str] = mapped_column(
        String(16), default="active", index=True, nullable=False
    )
    created_at: Mapped[datetime] = mapped_column(
        UTCDateTime(), default=utcnow, nullable=False
    )


class TrialRegistration(Base):
    """Server-authoritative free-trial period for a device fingerprint."""

    __tablename__ = "trial_registrations"

    device_fingerprint: Mapped[str] = mapped_column(String(64), primary_key=True)
    platform: Mapped[str] = mapped_column(String(32), nullable=False)
    started_at: Mapped[datetime] = mapped_column(
        UTCDateTime(), default=utcnow, nullable=False
    )
    last_seen_at: Mapped[datetime] = mapped_column(
        UTCDateTime(), default=utcnow, nullable=False
    )


class AdminAccount(Base):
    """The single dashboard administrator credential."""

    __tablename__ = "admin_accounts"

    id: Mapped[str] = mapped_column(String(16), primary_key=True, default="primary")
    username: Mapped[str] = mapped_column(
        String(60), unique=True, nullable=False
    )
    password_salt: Mapped[str] = mapped_column(String(64), nullable=False)
    password_hash: Mapped[str] = mapped_column(String(128), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        UTCDateTime(), default=utcnow, nullable=False
    )
