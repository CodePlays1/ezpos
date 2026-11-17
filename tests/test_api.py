from __future__ import annotations

import base64

from conftest import TEST_ADMIN_KEY, TEST_SIGNING_PASSWORD
from fastapi.testclient import TestClient

from app.core.crypto import b64url_encode, canonical_json
from app.main import create_app


def _fingerprint(_client: TestClient) -> str:
    return "a" * 64


def _device(fingerprint: str = "a" * 64) -> dict[str, str]:
    return {"fingerprint": fingerprint, "platform": "windows"}


def _activate(client: TestClient, token: str, fingerprint: str = "a" * 64):
    return client.post(
        "/api/v1/activations",
        json={"license_key": token, "device": _device(fingerprint)},
    )


def _verify(client: TestClient, token: str, fingerprint: str = "a" * 64):
    return client.post(
        "/api/v1/license/verify",
        json={"license_key": token, "device": _device(fingerprint)},
    )


def _status(client: TestClient, fingerprint: str = "a" * 64):
    return client.get(
        "/api/v1/license/status",
        params={"fingerprint": fingerprint, "platform": "windows"},
    )


def test_health_and_version(client, key_id):
    assert client.get("/health/live").json()["status"] == "ok"
    assert client.get("/health/ready").json()["status"] == "ready"
    assert client.get("/api/v1/device").status_code == 404

    version = client.get("/api/v1/version")
    assert version.status_code == 200
    assert version.json()["product"] == "PharmaPOS"
    assert key_id in version.json()["key_ids"]


def test_status_before_activation(client):
    response = _status(client)
    assert response.status_code == 200
    body = response.json()
    assert body["activated"] is False
    assert body["valid"] is False
    assert body["reason"] == "NOT_ACTIVATED"
    assert len(body["device"]["fingerprint"]) == 64


def test_trial_starts_on_server_and_cannot_be_reset_by_client(client):
    fingerprint = _fingerprint(client)
    first = client.post(
        "/api/v1/license/trial/status",
        json=_device(fingerprint),
    )
    assert first.status_code == 200
    first_body = first.json()
    assert first_body["valid"] is True
    assert first_body["reason"] == "TRIAL_ACTIVE"
    assert first_body["trial_days_remaining"] == 7

    repeated = client.post(
        "/api/v1/license/trial/status",
        json=_device(fingerprint),
    )
    assert repeated.status_code == 200
    assert repeated.json()["trial_ends_at"] == first_body["trial_ends_at"]

    forged_start = client.post(
        "/api/v1/license/trial/status",
        json={**_device(fingerprint), "started_at": "2099-01-01T00:00:00Z"},
    )
    assert forged_start.status_code == 422


def test_activated_device_cannot_start_a_new_trial(client, issue):
    token, _payload = issue(_fingerprint(client))
    assert _activate(client, token).status_code == 200

    trial = client.post(
        "/api/v1/license/trial/status",
        json=_device(),
    )
    assert trial.status_code == 200
    assert trial.json()["valid"] is False
    assert trial.json()["reason"] == "LICENSE_ACTIVATED"


def test_deactivated_license_does_not_restore_the_free_trial(client, issue):
    token, payload = issue(_fingerprint(client))
    assert _activate(client, token).status_code == 200
    deactivated = client.post(
        "/api/v1/admin/deactivate",
        json={"license_id": payload.license_id},
        headers={"X-Admin-Key": TEST_ADMIN_KEY},
    )
    assert deactivated.status_code == 200

    trial = client.post(
        "/api/v1/license/trial/status",
        json=_device(),
    )
    assert trial.status_code == 200
    assert trial.json()["valid"] is False
    assert trial.json()["reason"] == "TRIAL_EXPIRED"


def test_activation_requires_a_client_device_claim(client):
    response = client.post(
        "/api/v1/activations",
        json={"license_key": "x" * 64},
    )
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "VALIDATION_ERROR"


def test_activation_is_idempotent(client, issue):
    fingerprint = _fingerprint(client)
    token, payload = issue(fingerprint)

    first = _activate(client, token)
    assert first.status_code == 200
    body = first.json()
    assert body["already_activated"] is False
    assert body["license"]["license_id"] == payload.license_id
    assert body["license"]["license_type"] == "lifetime"
    assert body["license"]["device_limit"] == 1

    second = _activate(client, token)
    assert second.status_code == 200
    assert second.json()["already_activated"] is True
    assert second.json()["activation_id"] == body["activation_id"]

    status = _status(client).json()
    assert status["activated"] is True
    assert status["valid"] is True
    assert status["activation_id"] == body["activation_id"]
    assert status["license"]["customer_name"] == "Test Customer"


def test_verify_works_without_activating(client, issue):
    fingerprint = _fingerprint(client)
    token, payload = issue(fingerprint, features=["sales", "inventory"])

    response = _verify(client, token)
    assert response.status_code == 200
    body = response.json()
    assert body["valid"] is True
    assert body["license"]["license_id"] == payload.license_id
    assert body["license"]["features"] == ["sales", "inventory"]


def test_license_for_another_device_is_rejected(client, issue):
    _token, payload = issue("b" * 64)

    response = _activate(client, _token, "a" * 64)
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "DEVICE_MISMATCH"

    verify = _verify(client, _token, "a" * 64)
    assert verify.status_code == 403
    assert verify.json()["error"]["code"] == "DEVICE_MISMATCH"


def test_license_for_another_product_is_rejected(client, issue):
    token, _payload = issue(_fingerprint(client), product="DifferentPOS")

    response = _activate(client, token)
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "WRONG_PRODUCT"


def test_one_active_license_per_device(client, issue):
    fingerprint = _fingerprint(client)
    first_token, _ = issue(fingerprint)
    second_token, _ = issue(fingerprint)

    assert _activate(client, first_token).status_code == 200
    response = _activate(client, second_token)
    assert response.status_code == 409
    assert response.json()["error"]["code"] == "DEVICE_ALREADY_ACTIVATED"


def test_malformed_and_tampered_tokens(client, issue):
    malformed = _activate(client, "x" * 64)
    assert malformed.status_code == 400
    assert malformed.json()["error"]["code"] == "INVALID_TOKEN"

    token, _ = issue(_fingerprint(client))
    prefix, _payload, signature = token.split(".")
    forged_payload = canonical_json(
        {"license_id": "POS-EVIL99", "key_id": "f" * 16}
    )
    tampered = client.post(
        "/api/v1/activations",
        json={
            "license_key": f"{prefix}.{b64url_encode(forged_payload)}.{signature}",
            "device": _device(),
        },
    )
    assert tampered.status_code == 401
    assert tampered.json()["error"]["code"] == "INVALID_SIGNATURE"


def test_revocation_blocks_status_verify_and_activation(client, issue):
    fingerprint = _fingerprint(client)
    token, payload = issue(fingerprint)
    assert _activate(client, token).status_code == 200

    revoked = client.post(
        "/api/v1/admin/revoke",
        json={"license_id": payload.license_id, "reason": "refunded"},
        headers={"X-Admin-Key": TEST_ADMIN_KEY},
    )
    assert revoked.status_code == 200
    assert revoked.json()["revoked"] is True

    status = _status(client).json()
    assert status["activated"] is True
    assert status["valid"] is False
    assert status["reason"] == "LICENSE_REVOKED"

    verify = _verify(client, token)
    assert verify.status_code == 403
    assert verify.json()["error"]["code"] == "LICENSE_REVOKED"

    reactivate = _activate(client, token)
    assert reactivate.status_code == 403
    assert reactivate.json()["error"]["code"] == "LICENSE_REVOKED"


def test_admin_requires_the_configured_key(client):
    assert client.get("/api/v1/admin/activations").status_code == 401
    wrong = client.get(
        "/api/v1/admin/activations", headers={"X-Admin-Key": "wrong-key"}
    )
    assert wrong.status_code == 401
    allowed = client.get(
        "/api/v1/admin/activations", headers={"X-Admin-Key": TEST_ADMIN_KEY}
    )
    assert allowed.status_code == 200


def test_admin_lists_and_deactivates(client, issue):
    token, payload = issue(_fingerprint(client))
    assert _activate(client, token).status_code == 200

    listing = client.get(
        "/api/v1/admin/activations", headers={"X-Admin-Key": TEST_ADMIN_KEY}
    )
    assert listing.status_code == 200
    assert listing.json()[0]["license_id"] == payload.license_id
    assert "-" in listing.json()[0]["device_short_id"]

    deactivated = client.post(
        "/api/v1/admin/deactivate",
        json={"license_id": payload.license_id},
        headers={"X-Admin-Key": TEST_ADMIN_KEY},
    )
    assert deactivated.status_code == 200
    assert _status(client).json()["activated"] is False

    reactivated = _activate(client, token)
    assert reactivated.status_code == 200
    assert reactivated.json()["already_activated"] is False


def test_admin_can_restore_a_revoked_customer_license(client):
    headers = {"X-Admin-Key": TEST_ADMIN_KEY}
    created = client.post(
        "/api/v1/admin/licenses",
        headers=headers,
        json={"username": "restore-customer", "customer_name": "Restore Customer"},
    ).json()
    activation = client.post(
        "/api/v1/activations/claim",
        headers={},
        json={
            "username": created["username"],
            "license_code": created["activation_code"],
            "device": _device(),
        },
    )
    assert activation.status_code == 200
    fingerprint = activation.json()["device"]["fingerprint"]

    revoked = client.post(
        f"/api/v1/admin/licenses/{created['license_id']}/revoke",
        headers=headers,
        json={
            "license_id": created["license_id"],
            "reason": "Test revocation",
        },
    )
    assert revoked.status_code == 200
    assert _status(client, fingerprint).json()["reason"] == "LICENSE_REVOKED"

    restored = client.post(
        f"/api/v1/admin/licenses/{created['license_id']}/restore",
        headers=headers,
    )
    assert restored.status_code == 200
    assert restored.json() == {
        "license_id": created["license_id"],
        "restored": True,
    }
    status = _status(client, fingerprint).json()
    assert status["activated"] is True
    assert status["valid"] is True

    reactivated = client.post(
        "/api/v1/activations/claim",
        json={
            "username": created["username"],
            "license_code": created["activation_code"],
            "device": _device(fingerprint),
        },
    )
    assert reactivated.status_code == 200
    assert reactivated.json()["license"]["license_id"] == created["license_id"]

    repeated = client.post(
        f"/api/v1/admin/licenses/{created['license_id']}/restore",
        headers=headers,
    )
    assert repeated.status_code == 409
    assert repeated.json()["error"]["code"] == "LICENSE_NOT_REVOKED"


def test_admin_dashboard_serves_license_management_page(client):
    response = client.get("/admin")
    assert response.status_code == 200
    assert "License dashboard" in response.text


def test_admin_creates_license_and_customer_activates_with_username_and_code(client):
    created = client.post(
        "/api/v1/admin/licenses",
        headers={"X-Admin-Key": TEST_ADMIN_KEY},
        json={
            "username": "Customer.One",
            "customer_name": "Customer One",
            "customer_email": "one@example.com",
        },
    )
    assert created.status_code == 200
    account = created.json()
    assert account["username"] == "customer.one"
    assert account["activation_code"].startswith("EZP-")

    listed = client.get(
        "/api/v1/admin/licenses",
        headers={"X-Admin-Key": TEST_ADMIN_KEY},
    )
    assert listed.status_code == 200
    assert len(listed.json()) == 1
    assert "activation_code" not in listed.json()[0]

    activation = client.post(
        "/api/v1/activations/claim",
        json={
            "username": "CUSTOMER.ONE",
            "license_code": account["activation_code"],
            "device": _device(),
        },
    )
    assert activation.status_code == 200
    body = activation.json()
    assert body["license"]["license_id"] == account["license_id"]
    assert body["license_key"].startswith("POS1.")
    assert _verify(client, body["license_key"]).status_code == 200

    second_device = client.post(
        "/api/v1/activations/claim",
        json={
            "username": "customer.one",
            "license_code": account["activation_code"],
            "device": _device("b" * 64),
        },
    )
    assert second_device.status_code == 409
    assert second_device.json()["error"]["code"] == "LICENSE_ALREADY_ACTIVATED"

    reset = client.post(
        f"/api/v1/admin/licenses/{account['license_id']}/reset-code",
        headers={"X-Admin-Key": TEST_ADMIN_KEY},
    )
    assert reset.status_code == 200
    renewed_code = reset.json()["activation_code"]
    assert renewed_code != account["activation_code"]

    old_code = client.post(
        "/api/v1/activations/claim",
        json={
            "username": "customer.one",
            "license_code": account["activation_code"],
            "device": _device(),
        },
    )
    assert old_code.status_code == 401
    renewed_activation = client.post(
        "/api/v1/activations/claim",
        json={
            "username": "customer.one",
            "license_code": renewed_code,
            "device": _device(),
        },
    )
    assert renewed_activation.status_code == 200
    assert renewed_activation.json()["already_activated"] is True


def test_customer_activation_code_is_not_stored_or_exposed_after_creation(client):
    created = client.post(
        "/api/v1/admin/licenses",
        headers={"X-Admin-Key": TEST_ADMIN_KEY},
        json={"username": "customer2", "customer_name": "Customer Two"},
    ).json()
    wrong_code = client.post(
        "/api/v1/activations/claim",
        json={
            "username": "customer2",
            "license_code": "EZP-" + "0" * 48,
            "device": _device(),
        },
    )
    assert wrong_code.status_code == 401
    assert wrong_code.json()["error"]["code"] == "INVALID_CREDENTIALS"

    revoked = client.post(
        f"/api/v1/admin/licenses/{created['license_id']}/revoke",
        headers={"X-Admin-Key": TEST_ADMIN_KEY},
        json={"license_id": created["license_id"], "reason": "Refunded"},
    )
    assert revoked.status_code == 200
    denied = client.post(
        "/api/v1/activations/claim",
        json={
            "username": "customer2",
            "license_code": created["activation_code"],
            "device": _device(),
        },
    )
    assert denied.status_code == 401


def test_admin_can_reset_customer_device_binding(client):
    created = client.post(
        "/api/v1/admin/licenses",
        headers={"X-Admin-Key": TEST_ADMIN_KEY},
        json={"username": "move-device", "customer_name": "Device Move"},
    ).json()
    def activate(fingerprint):
        return client.post(
            "/api/v1/activations/claim",
            json={
                "username": "move-device",
                "license_code": created["activation_code"],
                "device": _device(fingerprint),
            },
        )

    assert activate("a" * 64).status_code == 200

    reset = client.post(
        f"/api/v1/admin/licenses/{created['license_id']}/deactivate",
        headers={"X-Admin-Key": TEST_ADMIN_KEY},
    )
    assert reset.status_code == 200
    assert activate("b" * 64).status_code == 200


def test_signed_backup_restores_records_and_rejects_edits(
    client, issue, settings_factory
):
    fingerprint = _fingerprint(client)
    assert client.post(
        "/api/v1/license/trial/status",
        json=_device(fingerprint),
    ).json()["valid"] is True
    token, _payload = issue(fingerprint)
    assert _activate(client, token).status_code == 200
    created = client.post(
        "/api/v1/admin/licenses",
        headers={"X-Admin-Key": TEST_ADMIN_KEY},
        json={"username": "backup-customer", "customer_name": "Backup Customer"},
    )
    assert created.status_code == 200

    backup_response = client.get(
        "/api/v1/admin/backup",
        headers={"X-Admin-Key": TEST_ADMIN_KEY},
    )
    assert backup_response.status_code == 200
    backup = backup_response.json()
    assert backup["format"] == "ezpos-license-backup"
    assert backup["data"]["activations"]
    assert backup["data"]["trial_registrations"]
    assert backup["data"]["customer_licenses"]

    edited = {**backup, "data": {**backup["data"]}}
    edited["data"]["trial_registrations"] = [
        {
            **backup["data"]["trial_registrations"][0],
            "started_at": "2099-01-01T00:00:00Z",
        }
    ]
    rejected = client.post(
        "/api/v1/admin/backup",
        headers={"X-Admin-Key": TEST_ADMIN_KEY},
        json=edited,
    )
    assert rejected.status_code == 422
    assert rejected.json()["error"]["code"] == "BACKUP_SIGNATURE_INVALID"

    restore_app = create_app(settings_factory(db_name="restored.db"))
    with TestClient(restore_app) as restore_client:
        restored = restore_client.post(
            "/api/v1/admin/backup",
            headers={"X-Admin-Key": TEST_ADMIN_KEY},
            json=backup,
        )
        assert restored.status_code == 200
        assert restored.json()["restored"] == {
            "activations": 1,
            "customer_licenses": 1,
            "trial_registrations": 1,
            "revoked_licenses": 0,
        }
        assert _status(restore_client, fingerprint).json()["valid"] is True
        assert restore_client.post(
            "/api/v1/license/trial/status",
            json=_device(fingerprint),
        ).json()["reason"] == "LICENSE_ACTIVATED"

        repeated = restore_client.post(
            "/api/v1/admin/backup",
            headers={"X-Admin-Key": TEST_ADMIN_KEY},
            json=backup,
        )
        assert repeated.status_code == 200
        assert repeated.json()["restored"] == {
            "activations": 0,
            "customer_licenses": 0,
            "trial_registrations": 0,
            "revoked_licenses": 0,
        }


def test_admin_license_creation_requires_admin_key(client):
    response = client.post(
        "/api/v1/admin/licenses",
        json={"username": "noadmin", "customer_name": "No Admin"},
    )
    assert response.status_code == 401


def test_admin_can_be_disabled(settings_factory):
    app = create_app(settings_factory(admin_enabled=False))
    with TestClient(app) as disabled_client:
        response = disabled_client.get("/api/v1/admin/activations")
        assert response.status_code == 404
        assert response.json()["error"]["code"] == "ADMIN_DISABLED"


def test_admin_dashboard_first_run_setup_and_sign_in(settings_factory):
    settings = settings_factory(admin_enabled=False).model_copy(
        update={"admin_enabled": True, "admin_api_key": None}
    )
    app = create_app(settings)
    with TestClient(app) as setup_client:
        dashboard = setup_client.get("/admin")
        assert dashboard.status_code == 200
        assert "EZ POS License Admin" in dashboard.text

        status = setup_client.get("/api/v1/admin/setup-status")
        assert status.status_code == 200
        setup_token = status.json()["setup_token"]

        failed_setup = setup_client.post(
            "/api/v1/admin/setup",
            json={
                "setup_token": setup_token,
                "username": "ezadmin",
                "password": "a-secure-admin-password",
                "signing_key_password": "incorrect-password",
            },
        )
        assert failed_setup.status_code == 400
        assert failed_setup.json()["error"]["code"] == "SIGNING_KEY_UNLOCK_FAILED"

        setup = setup_client.post(
            "/api/v1/admin/setup",
            json={
                "setup_token": setup_token,
                "username": "ezadmin",
                "password": "a-secure-admin-password",
                "signing_key_password": TEST_SIGNING_PASSWORD,
            },
        )
        assert setup.status_code == 200
        assert setup.json()["signing_ready"] is True

        status = setup_client.get("/api/v1/admin/setup-status")
        assert status.status_code == 200
        assert status.json()["setup_required"] is False
        assert "setup_token" not in status.json()

        authorization = base64.b64encode(
            b"ezadmin:a-secure-admin-password"
        ).decode("ascii")
        licenses = setup_client.get(
            "/api/v1/admin/activations",
            headers={"Authorization": f"Basic {authorization}"},
        )
        assert licenses.status_code == 200
        created = setup_client.post(
            "/api/v1/admin/licenses",
            headers={"Authorization": f"Basic {authorization}"},
            json={"username": "customer1", "customer_name": "Customer One"},
        )
        assert created.status_code == 200
        assert created.json()["activation_code"].startswith("EZP-")

        invalid_auth = setup_client.get(
            "/api/v1/admin/activations",
            headers={
                "Authorization": "Basic "
                + base64.b64encode(b"ezadmin:wrong").decode("ascii")
            },
        )
        assert invalid_auth.status_code == 401

        second_setup = setup_client.post(
            "/api/v1/admin/setup",
            json={
                "setup_token": setup_token,
                "username": "another",
                "password": "another-secure-password",
                "signing_key_password": TEST_SIGNING_PASSWORD,
            },
        )
        assert second_setup.status_code == 409


def test_validation_errors_are_structured(client):
    response = client.post("/api/v1/activations", json={})
    assert response.status_code == 422
    body = response.json()["error"]
    assert body["code"] == "VALIDATION_ERROR"
    assert body["request_id"]
    assert body["details"]


def test_rate_limiter_returns_retry_after(settings_factory):
    app = create_app(settings_factory(rate_limit_per_minute=1))
    with TestClient(app) as limited_client:
        first = limited_client.post(
            "/api/v1/license/verify",
            json={"license_key": "x" * 64, "device": _device()},
        )
        assert first.status_code == 400

        second = limited_client.post(
            "/api/v1/license/verify",
            json={"license_key": "x" * 64, "device": _device()},
        )
        assert second.status_code == 429
        assert second.json()["error"]["code"] == "RATE_LIMITED"
        assert "Retry-After" in second.headers
