from __future__ import annotations

import pytest
from pydantic import ValidationError

from app.config import Settings
from app.core.device import (
    compute_device_identity,
    fingerprint_from_components,
    format_short_id,
)
from app.core.exceptions import DeviceIdentityError


def test_override_fingerprint_is_stable(settings):
    first = compute_device_identity(settings)
    second = compute_device_identity(settings)

    assert first.fingerprint == second.fingerprint
    assert len(first.fingerprint) == 64
    assert first.short_id == format_short_id(first.fingerprint)
    assert "-" in first.short_id


def test_different_device_override_changes_fingerprint(settings):
    other = settings.model_copy(update={"device_override": "device-b"})

    assert (
        compute_device_identity(settings).fingerprint
        != compute_device_identity(other).fingerprint
    )


def test_salt_changes_fingerprint(settings):
    other = settings.model_copy(
        update={"device_fingerprint_salt": "another-long-device-salt-value"}
    )

    assert (
        compute_device_identity(settings).fingerprint
        != compute_device_identity(other).fingerprint
    )


def test_component_order_does_not_matter():
    components_a = [("a", "1"), ("b", "2")]
    components_b = [("b", "2"), ("a", "1")]

    assert fingerprint_from_components(
        components_a, "a-long-enough-salt"
    ) == fingerprint_from_components(components_b, "a-long-enough-salt")


def test_empty_components_are_rejected():
    with pytest.raises(DeviceIdentityError):
        fingerprint_from_components([], "a-long-enough-salt")


def test_production_rejects_device_override():
    with pytest.raises(ValidationError):
        Settings(
            environment="production",
            device_override="device-a",
            admin_enabled=False,
        )
