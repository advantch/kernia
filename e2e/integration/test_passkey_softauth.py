"""Full WebAuthn round-trip using a software authenticator.

Exercises generate-register-options → SoftAuthenticator.register →
verify-registration → generate-authenticate-options →
SoftAuthenticator.authenticate → verify-authentication.

Unlike the passkey package's unit tests (which monkeypatch the webauthn
verify functions), this drives real WebAuthn crypto end-to-end through the
upstream-aligned endpoints.
"""

from __future__ import annotations

import pytest
from better_auth.auth import init
from better_auth.plugins import email_and_password
from better_auth.types.init_options import BetterAuthOptions
from better_auth_memory_adapter import memory_adapter
from better_auth_passkey import passkey
from better_auth_test_utils import ASGIDriver, SoftAuthenticator
from webauthn.helpers import base64url_to_bytes

RP_ID = "localhost"
ORIGIN = "http://localhost:3000"


def _build() -> tuple[ASGIDriver, object]:
    auth = init(
        BetterAuthOptions(
            database=memory_adapter(),
            secret="test-secret",
            base_url=ORIGIN,
            plugins=[
                email_and_password(),
                passkey(rp_id=RP_ID, rp_name="Test", origin=ORIGIN),
            ],
        )
    )
    return ASGIDriver(app=auth.router.mount()), auth


async def _sign_up(driver: ASGIDriver, email: str) -> dict:
    r = await driver.request(
        "POST", "/sign-up/email", json_body={"email": email, "password": "correcthorse"}
    )
    assert r.status == 200, r.json()
    return r.json()["user"]


@pytest.mark.asyncio
async def test_full_passkey_register_and_authenticate() -> None:
    driver, auth = _build()
    await _sign_up(driver, "user@example.com")

    authenticator = SoftAuthenticator()

    # ---- registration ----
    r = await driver.request("GET", "/passkey/generate-register-options")
    assert r.status == 200, r.json()
    options = r.json()
    challenge = base64url_to_bytes(options["challenge"])

    attestation = authenticator.register(
        challenge=challenge, origin=ORIGIN, rp_id=RP_ID
    )
    r = await driver.request(
        "POST", "/passkey/verify-registration", json_body={"response": attestation}
    )
    assert r.status == 200, r.json()
    cred_id_b64 = r.json()["credentialID"]
    assert cred_id_b64

    # The passkey row landed in the DB.
    rows = await auth.context.adapter.find_many(model="passkey", where=())
    assert len(rows) == 1
    assert rows[0]["credentialID"] == cred_id_b64

    # ---- authentication ----
    # Fresh ASGIDriver so we don't carry the email-password session
    # (usernameless/discoverable-credential flow).
    auth_driver = ASGIDriver(app=auth.router.mount())
    r = await auth_driver.request("GET", "/passkey/generate-authenticate-options")
    assert r.status == 200, r.json()
    auth_options = r.json()
    auth_challenge = base64url_to_bytes(auth_options["challenge"])

    assertion = authenticator.authenticate(
        challenge=auth_challenge,
        origin=ORIGIN,
        rp_id=RP_ID,
        credential_id=cred_id_b64,
    )
    r = await auth_driver.request(
        "POST", "/passkey/verify-authentication", json_body={"response": assertion}
    )
    assert r.status == 200, r.json()

    # Session cookie was set by the verify handler.
    assert "better-auth.session_token" in auth_driver.cookies

    # /get-session returns the right user.
    r = await auth_driver.request("GET", "/get-session")
    assert r.status == 200
    assert r.json()["user"]["email"] == "user@example.com"


@pytest.mark.asyncio
async def test_authenticate_rejects_wrong_signature() -> None:
    """An authenticator that didn't register MUST fail authentication."""
    driver, auth = _build()
    await _sign_up(driver, "user@example.com")

    registered = SoftAuthenticator()

    # Register the real one
    r = await driver.request("GET", "/passkey/generate-register-options")
    challenge = base64url_to_bytes(r.json()["challenge"])
    attestation = registered.register(challenge=challenge, origin=ORIGIN, rp_id=RP_ID)
    r = await driver.request(
        "POST", "/passkey/verify-registration", json_body={"response": attestation}
    )
    assert r.status == 200, r.json()
    cred_id_b64 = r.json()["credentialID"]

    # Build a DIFFERENT authenticator with its own keypair — its signature
    # won't verify against the stored public key.
    impostor = SoftAuthenticator()
    impostor.register(challenge=b"x" * 32, origin=ORIGIN, rp_id=RP_ID)

    auth_driver = ASGIDriver(app=auth.router.mount())
    r = await auth_driver.request("GET", "/passkey/generate-authenticate-options")
    auth_challenge = base64url_to_bytes(r.json()["challenge"])

    assertion = impostor.authenticate(
        challenge=auth_challenge, origin=ORIGIN, rp_id=RP_ID
    )
    # Swap the credentialId so the server looks up the real public key; the
    # impostor's private key won't match, so signature verify must fail.
    assertion["id"] = cred_id_b64
    assertion["rawId"] = cred_id_b64

    r = await auth_driver.request(
        "POST", "/passkey/verify-authentication", json_body={"response": assertion}
    )
    assert r.status >= 400
    # Server should not have set a session cookie.
    assert "better-auth.session_token" not in auth_driver.cookies


@pytest.mark.asyncio
async def test_register_rejects_tampered_challenge() -> None:
    """If the attestation signs a challenge the server didn't issue, registration fails."""
    driver, _ = _build()
    await _sign_up(driver, "user@example.com")
    authenticator = SoftAuthenticator()

    # Get the real challenge, then sign a DIFFERENT challenge instead.
    r = await driver.request("GET", "/passkey/generate-register-options")
    assert r.status == 200

    fake_attestation = authenticator.register(
        challenge=b"\x00" * 32, origin=ORIGIN, rp_id=RP_ID
    )
    r = await driver.request(
        "POST", "/passkey/verify-registration", json_body={"response": fake_attestation}
    )
    assert r.status == 400
    assert r.json()["code"] == "FAILED_TO_VERIFY_REGISTRATION"
