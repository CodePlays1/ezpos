from __future__ import annotations

import hashlib

from fastapi.testclient import TestClient

from app.main import create_app


def _fingerprint(device: str) -> str:
    return hashlib.sha256(device.encode("utf-8")).hexdigest()


def _device(fingerprint: str) -> dict[str, str]:
    return {"fingerprint": fingerprint, "platform": "windows"}


def test_activation_survives_restart_without_network(settings_factory, issue):
    first_settings = settings_factory(device="device-a", db_name="shared.db")
    first_app = create_app(first_settings)
    with TestClient(first_app) as first_client:
        fingerprint = _fingerprint("device-a")
        token, payload = issue(fingerprint)
        activated = first_client.post(
            "/api/v1/activations",
            json={"license_key": token, "device": _device(fingerprint)},
        )
        assert activated.status_code == 200

    second_settings = settings_factory(device="device-a", db_name="shared.db")
    second_app = create_app(second_settings)
    with TestClient(second_app) as second_client:
        status = second_client.get(
            "/api/v1/license/status",
            params={"fingerprint": fingerprint, "platform": "windows"},
        ).json()
        assert status["activated"] is True
        assert status["valid"] is True
        assert status["license"]["license_id"] == payload.license_id

        verified = second_client.post(
            "/api/v1/license/verify",
            json={"license_key": token, "device": _device(fingerprint)},
        )
        assert verified.status_code == 200


def test_copied_database_and_license_fail_on_another_device(
    settings_factory, issue
):
    first_settings = settings_factory(device="device-a", db_name="shared.db")
    first_app = create_app(first_settings)
    with TestClient(first_app) as first_client:
        fingerprint = _fingerprint("device-a")
        token, _payload = issue(fingerprint)
        assert (
            first_client.post(
                "/api/v1/activations",
                json={"license_key": token, "device": _device(fingerprint)},
            ).status_code
            == 200
        )

    other_settings = settings_factory(device="device-b", db_name="shared.db")
    other_app = create_app(other_settings)
    with TestClient(other_app) as other_client:
        other_fingerprint = _fingerprint("device-b")
        status = other_client.get(
            "/api/v1/license/status",
            params={"fingerprint": other_fingerprint, "platform": "windows"},
        ).json()
        assert status["activated"] is False
        assert status["valid"] is False

        activation = other_client.post(
            "/api/v1/activations",
            json={
                "license_key": token,
                "device": _device(other_fingerprint),
            },
        )
        assert activation.status_code == 403
        assert activation.json()["error"]["code"] == "DEVICE_MISMATCH"
