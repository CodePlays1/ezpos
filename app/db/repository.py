from __future__ import annotations

from datetime import timedelta

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.time import utcnow
from app.db.models import (
    Activation,
    AdminAccount,
    CustomerLicense,
    RevokedLicense,
    TrialRegistration,
)


async def get_admin_account(session: AsyncSession) -> AdminAccount | None:
    return await session.get(AdminAccount, "primary")


async def get_activation_by_license_id(
    session: AsyncSession, license_id: str
) -> Activation | None:
    result = await session.execute(
        select(Activation).where(Activation.license_id == license_id)
    )
    return result.scalar_one_or_none()


async def get_activation_by_device(
    session: AsyncSession, device_fingerprint: str
) -> Activation | None:
    result = await session.execute(
        select(Activation).where(
            Activation.device_fingerprint == device_fingerprint,
            Activation.status == "active",
        )
    )
    return result.scalar_one_or_none()


async def ensure_trial_consumed(
    session: AsyncSession, device_fingerprint: str, platform: str
) -> None:
    registration = await session.get(TrialRegistration, device_fingerprint)
    if registration is None:
        now = utcnow()
        session.add(
            TrialRegistration(
                device_fingerprint=device_fingerprint,
                platform=platform,
                started_at=now - timedelta(days=7, seconds=1),
                last_seen_at=now,
            )
        )


async def list_activations(session: AsyncSession) -> list[Activation]:
    result = await session.execute(
        select(Activation).order_by(Activation.activated_at.desc())
    )
    return list(result.scalars().all())


async def delete_activation_by_license_id(
    session: AsyncSession, license_id: str
) -> bool:
    customer_license = await session.get(CustomerLicense, license_id)
    if customer_license is not None:
        customer_license.device_fingerprint = None
    result = await session.execute(
        delete(Activation).where(Activation.license_id == license_id)
    )
    await session.commit()
    return bool(result.rowcount)


async def is_license_revoked(session: AsyncSession, license_id: str) -> bool:
    return await session.get(RevokedLicense, license_id) is not None


async def revoke_license(
    session: AsyncSession, license_id: str, reason: str
) -> RevokedLicense:
    customer_license = await session.get(CustomerLicense, license_id)
    if customer_license is not None:
        customer_license.status = "revoked"
    existing = await session.get(RevokedLicense, license_id)
    now = utcnow()
    if existing is None:
        existing = RevokedLicense(
            license_id=license_id, reason=reason, revoked_at=now
        )
        session.add(existing)
    else:
        existing.reason = reason
        existing.revoked_at = now
    await session.commit()
    await session.refresh(existing)
    return existing


async def list_revocations(session: AsyncSession) -> list[RevokedLicense]:
    result = await session.execute(
        select(RevokedLicense).order_by(RevokedLicense.revoked_at.desc())
    )
    return list(result.scalars().all())


async def get_customer_license(
    session: AsyncSession, username: str
) -> CustomerLicense | None:
    result = await session.execute(
        select(CustomerLicense).where(CustomerLicense.username == username)
    )
    return result.scalar_one_or_none()


async def get_customer_license_by_id(
    session: AsyncSession, license_id: str
) -> CustomerLicense | None:
    return await session.get(CustomerLicense, license_id)


async def list_customer_licenses(
    session: AsyncSession,
) -> list[CustomerLicense]:
    result = await session.execute(
        select(CustomerLicense).order_by(CustomerLicense.created_at.desc())
    )
    return list(result.scalars().all())
