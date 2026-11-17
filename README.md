# EZ POS license API

FastAPI service for issuing, activating, and checking lifetime, single-device licenses. The Electron app verifies each signed Ed25519 license locally, so an activated POS remains usable when the API or internet connection is unavailable. The app attempts an online verification every two minutes; the API can report signed-license revocations while reachable.

The seven-day trial is server-authoritative: `POST /api/v1/license/trial/status` records its start against the device fingerprint and returns the fixed expiry. Unactivated POS installations must reach the API at startup and every two minutes; local trial timestamps are not used to grant access.

## Back up free-instance data

The admin dashboard includes **Download backup** and **Restore signed backup**. Download a backup after creating licenses or making other important changes, and keep it somewhere private. It contains customer information, activation data, device fingerprints, and trial records; it is signed to detect edits but is not encrypted. Do not share it or commit it to source control.

Restore accepts an unmodified backup signed by a key trusted by the service. It adds missing licenses and activations, merges trial records using the earliest recorded start time, and preserves existing records and revocations. It does not roll back or replace records already present. A backup only contains data from when it was downloaded, so changes made after that download cannot be recovered. Backups also need to be verified with the public key matching the signing key that created them.

## Render deployment

Create a Render Blueprint from the repository using `render.yaml`. It deploys this directory as a Python web service, provisions PostgreSQL, and uses `/health/ready` as the health check. Set `POS_LICENSE_PUBLIC_KEY_B64` in the Render dashboard to the **public** base64 key printed by `scripts/generate_keys.py`. The API refuses to start without a trusted public key. Configure any custom domains in `POS_LICENSE_ALLOWED_HOSTS` as a JSON string array, for example `["licenses.example.com"]`.

Set `POS_LICENSE_PUBLIC_KEY_B64` to the public key printed by `scripts/generate_keys.py`. Configure `POS_LICENSE_SIGNING_PRIVATE_KEY_B64` as a Render secret containing the base64-encoded encrypted Ed25519 private key (PEM or DER). Long values must be pasted as a single line; if your editor wraps the base64, either join the lines or upload the encrypted key as a Render Secret File and set `POS_LICENSE_SIGNING_PRIVATE_KEY_FILE` to its path instead. The private key must match the public key. The dashboard submits its encryption password to unlock the key; the app does not persist the password or store it in the browser. The unlocked private key remains in server-process memory until restart.

For signing-key rotation, commit all old and new public PEMs under `keys/public`; the service loads these trusted keys alongside `POS_LICENSE_PUBLIC_KEY_B64`. Set that variable to the new key's raw-public-key base64 value, and update the encrypted private-key and password secrets together. This keeps previously issued licenses verifiable while the new key signs future licenses. Never commit either the private key or its password.

Open `https://<your-service>/admin`. On first use, retrieve the one-time setup code from the service logs, then create the dashboard username/password and unlock the signing key with its encryption password. Keep the setup code private; it is invalidated after successful setup. The dashboard stores the admin password as a salted scrypt hash. On later server starts, sign in and unlock the signing key again if prompted. Create customer accounts and deliver activation codes securely. The dashboard's Device activations table lists every device binding, including activations not created from a dashboard customer account; admins can reset, revoke, or restore those licenses there. Customer activation codes are shown only when first created or reset; they are not stored in readable form and cannot be retrieved later. Restoring removes the server-side revocation and preserves the existing activation and device binding.

The default in-process rate limiter and SQLite configuration are suitable for local development. The Render blueprint uses PostgreSQL, one web process, and the configured single-instance limiter. Before adding multiple web instances, replace the limiter with a shared store and configure trusted proxy handling. Keep PostgreSQL backups enabled for production.

## Local development

From `PosBackend`:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt -r requirements-dev.txt
python scripts\generate_keys.py
python run.py
```

Key generation now always encrypts the private key. Choose and confirm a password when prompted, then enter that same password in the `/admin` first-run setup form and whenever the dashboard asks to unlock the signing key. For unattended generation, set `POS_LICENSE_SIGNING_KEY_PASSWORD` in the process environment before running the script; do not put the password in source control. The key-generation command stores the encrypted signing key under `keys/private`, the verifier's public key under `keys/public`, and a copy under the Electron app's `licensing/public` directory. Public PEM files are safe to commit and are needed by Render to verify existing licenses during key rotation. Back up the private key securely and keep it out of source control and customer builds. Only public keys are deployed with the desktop app.

On first start, a one-time dashboard setup code is written to the server log and prefilled in `/admin` when accessed from localhost.

## API

- `GET /health/live` and `GET /health/ready`: process and readiness checks.
- `POST /api/v1/activations`: verify and record a pre-signed license token for the supplied client fingerprint.
- `POST /api/v1/activations/claim`: activate a dashboard-created username/license code and return its signed, device-bound token.
- `POST /api/v1/license/verify`: online signature, device, and revocation check.
- `POST /api/v1/license/recover`: recover the signed token for an existing activation bound to the presented device fingerprint.
- `GET /api/v1/license/status?fingerprint=...&platform=...`: activation status for a client identity.
- `POST /api/v1/license/trial/status`: start or check the seven-day trial for a device fingerprint.
- `GET /api/v1/version`: service/product and trusted key IDs.
- `/admin`: Jinja-rendered browser dashboard for first-time setup, admin sign-in, signing-key unlock, and customer license management.
- `/api/v1/admin/*`: protected by the dashboard admin account (Basic authentication); the legacy `X-Admin-Key` mechanism remains available only when explicitly configured.

Activation and verification requests include the POS-generated device fingerprint and platform. The server does not fingerprint the Render host. The private key is required server-side to issue signed tokens for dashboard-created licenses. The UI never exposes the private-key bytes; only the unlock password is submitted to the API over HTTPS.

## Issue a license

For the dashboard workflow, create a username and license code at `/admin`, then provide both to the customer. The POS collects only that username and code; it sends the device fingerprint in the background. The first activation binds the license to that device and returns the signed token used for subsequent offline verification. The code can restore activation on the same device; reset the device binding in the dashboard to move it.

The CLI can still issue pre-signed licenses for a known device. Collect the full device fingerprint from the POS activation request/logging workflow, then run:

```powershell
python scripts\issue_license.py --device-fingerprint <64-character-fingerprint> --customer-name "Customer name"
```

Use the signing key password when prompted and deliver the token to the customer. Licenses are lifetime and limited to one device. The client must be online to activate initially; local signature verification supports subsequent offline use.
