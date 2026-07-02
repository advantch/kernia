"""Passkey plugin tests.

Ported 1:1 from ``reference/packages/passkey/src/passkey.test.ts``. The upstream
suite mocks ``@simplewebauthn/server``'s ``verifyRegistrationResponse`` /
``verifyAuthenticationResponse``; here we monkeypatch the equivalent functions on
:mod:`kernia_passkey.webauthn_server` (the seam ``routes.py`` calls through).

Test names mirror the vitest ``it(...)`` titles. Cases that depend purely on the
crypto verifier are exercised through the mock, identical to upstream.
"""

from __future__ import annotations

import pytest
from kernia.auth import init
from kernia.plugins import email_and_password
from kernia.types.adapter import Where
from kernia.types.init_options import KerniaOptions
from kernia_memory_adapter import memory_adapter
from kernia_passkey import (
    PasskeyOptions,
    PasskeyRegistrationOptions,
    passkey,
    webauthn_server,
)
from kernia_passkey.webauthn_server import (
    AuthenticationInfo,
    RegistrationInfo,
    VerifiedAuthenticationResponse,
    VerifiedCredential,
    VerifiedRegistrationResponse,
)
from kernia_test_utils import ASGIDriver

ORIGIN = "http://localhost:3000"


# ----- fixtures / mocks ------------------------------------------------------

MOCK_REGISTRATION_RESPONSE = {
    "id": "credential-id",
    "response": {"transports": ["internal"]},
}


def _mock_registration_verification() -> VerifiedRegistrationResponse:
    return VerifiedRegistrationResponse(
        verified=True,
        registration_info=RegistrationInfo(
            aaguid="test-aaguid",
            credential_device_type="singleDevice",
            credential_backed_up=False,
            credential=VerifiedCredential(
                id="credential-id", public_key=bytes([1, 2, 3]), counter=0
            ),
        ),
    )


@pytest.fixture(autouse=True)
def _reset_webauthn_mocks():
    orig_reg = webauthn_server.verify_registration_response
    orig_auth = webauthn_server.verify_authentication_response
    yield
    webauthn_server.verify_registration_response = orig_reg
    webauthn_server.verify_authentication_response = orig_auth


def _build(plugin=None) -> tuple[ASGIDriver, object, object]:
    adapter = memory_adapter()
    auth = init(
        KerniaOptions(
            database=adapter,
            secret="test-secret-key",
            plugins=[email_and_password(), plugin or passkey()],
        )
    )
    return ASGIDriver(app=auth.router.mount()), adapter, auth


async def _sign_up(driver: ASGIDriver, email: str = "test@test.com") -> str:
    r = await driver.request(
        "POST",
        "/sign-up/email",
        json_body={"email": email, "password": "password123", "name": "Test"},
    )
    assert r.status == 200, r.json()
    return r.json()["user"]["id"]


# ----- tests -----------------------------------------------------------------


async def test_should_generate_register_options() -> None:
    driver, _, _ = _build()
    await _sign_up(driver)
    r = await driver.request("GET", "/passkey/generate-register-options")
    assert r.status == 200, r.json()
    options = r.json()
    assert "challenge" in options
    assert "rp" in options
    assert "user" in options
    assert "pubKeyCredParams" in options
    # The signed challenge cookie is set.
    set_cookie = [v for k, v in r.headers if k.lower() == "set-cookie"]
    assert any("better-auth-passkey" in c for c in set_cookie)


async def test_should_generate_register_options_without_session_when_resolve_user() -> None:
    plugin = passkey(
        PasskeyOptions(
            registration=PasskeyRegistrationOptions(
                require_session=False,
                resolve_user=lambda **_: {
                    "id": "pre-auth-user",
                    "name": "pre-auth@example.com",
                },
            )
        )
    )
    driver, _, _ = _build(plugin)
    r = await driver.request("GET", "/passkey/generate-register-options")
    assert r.status == 200, r.json()
    options = r.json()
    assert "challenge" in options
    assert "rp" in options
    assert "user" in options
    assert "pubKeyCredParams" in options


async def test_should_require_resolve_user_when_session_not_available() -> None:
    plugin = passkey(PasskeyOptions(registration=PasskeyRegistrationOptions(require_session=False)))
    driver, _, _ = _build(plugin)
    r = await driver.request("GET", "/passkey/generate-register-options")
    assert r.status == 400
    assert r.json()["code"] == "RESOLVE_USER_REQUIRED"


async def test_should_call_after_verification_and_allow_user_id_override() -> None:
    calls: list[dict] = []

    async def after_verification(**kwargs):
        calls.append(kwargs)
        return {"userId": linked["id"]}

    plugin = passkey(
        PasskeyOptions(
            origin=ORIGIN,
            registration=PasskeyRegistrationOptions(
                require_session=False,
                resolve_user=lambda **_: {
                    "id": "pre-auth-user-id",
                    "name": "pre-auth@example.com",
                    "displayName": "Pre-auth user",
                },
                after_verification=after_verification,
            ),
        )
    )
    driver, _, _ = _build(plugin)
    r = await driver.request(
        "POST",
        "/sign-up/email",
        json_body={
            "email": "linked-user@example.com",
            "password": "test123456",
            "name": "Linked User",
        },
    )
    linked = r.json()["user"]
    # Sign out so there's no active session (registration runs pre-auth).
    driver.cookies.clear()

    webauthn_server.verify_registration_response = lambda **_: _mock_registration_verification()

    await driver.request(
        "GET",
        "/passkey/generate-register-options",
        query="context=link-token",
        headers={"origin": ORIGIN},
    )
    r = await driver.request(
        "POST",
        "/passkey/verify-registration",
        json_body={"response": MOCK_REGISTRATION_RESPONSE},
        headers={"origin": ORIGIN},
    )
    assert r.status == 200, r.json()
    assert calls, "afterVerification was not called"
    assert calls[0].get("context") == "link-token"
    assert r.json()["userId"] == linked["id"]


async def test_should_reject_invalid_user_id_from_after_verification() -> None:
    called: list[bool] = []

    async def after_verification(**_kwargs):
        called.append(True)
        return {"userId": 123}

    plugin = passkey(
        PasskeyOptions(
            origin=ORIGIN,
            registration=PasskeyRegistrationOptions(
                require_session=False,
                resolve_user=lambda **_: {
                    "id": resolved["id"],
                    "name": "pre-auth@example.com",
                },
                after_verification=after_verification,
            ),
        )
    )
    driver, _, _ = _build(plugin)
    r = await driver.request(
        "POST",
        "/sign-up/email",
        json_body={
            "email": "invalid-user-id@example.com",
            "password": "test123456",
            "name": "Invalid User Id Test",
        },
    )
    resolved = r.json()["user"]
    driver.cookies.clear()

    webauthn_server.verify_registration_response = lambda **_: _mock_registration_verification()

    await driver.request(
        "GET",
        "/passkey/generate-register-options",
        query="context=link-token",
        headers={"origin": ORIGIN},
    )
    r = await driver.request(
        "POST",
        "/passkey/verify-registration",
        json_body={"response": MOCK_REGISTRATION_RESPONSE},
        headers={"origin": ORIGIN},
    )
    assert r.status >= 400
    assert r.json()["code"] == "RESOLVED_USER_INVALID"
    assert called


async def test_should_reject_after_verification_mismatching_session_user() -> None:
    called: list[bool] = []

    async def after_verification(**_kwargs):
        called.append(True)
        return {"userId": "different-user-id"}

    plugin = passkey(
        PasskeyOptions(
            origin=ORIGIN,
            registration=PasskeyRegistrationOptions(after_verification=after_verification),
        )
    )
    driver, _, _ = _build(plugin)
    await _sign_up(driver)

    webauthn_server.verify_registration_response = lambda **_: _mock_registration_verification()

    await driver.request("GET", "/passkey/generate-register-options", headers={"origin": ORIGIN})
    r = await driver.request(
        "POST",
        "/passkey/verify-registration",
        json_body={"response": MOCK_REGISTRATION_RESPONSE},
        headers={"origin": ORIGIN},
    )
    assert r.status >= 400
    assert r.json()["code"] == "YOU_ARE_NOT_ALLOWED_TO_REGISTER_THIS_PASSKEY"
    assert called


async def test_should_generate_authenticate_options() -> None:
    driver, _, _ = _build()
    await _sign_up(driver)
    r = await driver.request("GET", "/passkey/generate-authenticate-options")
    assert r.status == 200, r.json()
    options = r.json()
    assert "challenge" in options
    assert "rpId" in options
    assert "allowCredentials" in options
    assert "userVerification" in options


async def test_should_generate_authenticate_options_without_session() -> None:
    driver, _, _ = _build()
    r = await driver.request("GET", "/passkey/generate-authenticate-options")
    assert r.status == 200, r.json()
    options = r.json()
    assert "challenge" in options
    assert "rpId" in options
    assert "userVerification" in options


async def _seed_passkey(adapter, user_id: str, credential_id: str = "mockCredentialID"):
    return await adapter.create(
        model="passkey",
        data={
            "userId": user_id,
            "publicKey": "mockPublicKey",
            "name": "mockName",
            "counter": 0,
            "deviceType": "singleDevice",
            "credentialID": credential_id,
            "createdAt": 0,
            "backedUp": False,
            "transports": "mockTransports",
            "aaguid": "mockAAGUID",
        },
    )


async def test_should_list_user_passkeys() -> None:
    driver, adapter, _ = _build()
    user_id = await _sign_up(driver)
    await _seed_passkey(adapter, user_id)

    r = await driver.request("GET", "/passkey/list-user-passkeys")
    assert r.status == 200, r.json()
    passkeys = r.json()
    assert isinstance(passkeys, list)
    assert "id" in passkeys[0]
    assert "userId" in passkeys[0]
    assert "publicKey" in passkeys[0]
    assert "credentialID" in passkeys[0]
    assert "aaguid" in passkeys[0]


async def test_should_update_a_passkey() -> None:
    driver, adapter, _ = _build()
    user_id = await _sign_up(driver)
    pk = await _seed_passkey(adapter, user_id)

    r = await driver.request(
        "POST",
        "/passkey/update-passkey",
        json_body={"id": pk["id"], "name": "newName"},
    )
    assert r.status == 200, r.json()
    assert r.json()["passkey"]["name"] == "newName"


async def test_should_not_delete_a_passkey_that_doesnt_exist() -> None:
    driver, _, _ = _build()
    await _sign_up(driver)
    r = await driver.request("POST", "/passkey/delete-passkey", json_body={"id": "mockPasskeyId"})
    assert r.status >= 400
    assert r.json()["code"] == "PASSKEY_NOT_FOUND"


async def test_should_delete_a_passkey() -> None:
    driver, adapter, _ = _build()
    user_id = await _sign_up(driver)
    pk = await _seed_passkey(adapter, user_id)
    r = await driver.request("POST", "/passkey/delete-passkey", json_body={"id": pk["id"]})
    assert r.status == 200, r.json()
    assert r.json()["status"] is True


async def test_should_not_allow_deleting_another_users_passkey() -> None:
    driver, adapter, _ = _build()
    user_a = await _sign_up(driver, email="ownerA@test.com")
    pk = await _seed_passkey(adapter, user_a, credential_id="cross-user-delete-test")
    # Switch to attacker B.
    driver.cookies.clear()
    await driver.request(
        "POST",
        "/sign-up/email",
        json_body={
            "email": "attacker-delete@test.com",
            "password": "password123",
            "name": "Attacker",
        },
    )
    r = await driver.request("POST", "/passkey/delete-passkey", json_body={"id": pk["id"]})
    assert r.status >= 400
    still = await adapter.find_one(model="passkey", where=(Where(field="id", value=pk["id"]),))
    assert still is not None


async def test_should_not_allow_updating_another_users_passkey() -> None:
    driver, adapter, _ = _build()
    user_a = await _sign_up(driver, email="ownerU@test.com")
    pk = await _seed_passkey(adapter, user_a, credential_id="cross-user-update-test")
    await adapter.update(
        model="passkey",
        where=(Where(field="id", value=pk["id"]),),
        update={"name": "original-name"},
    )
    driver.cookies.clear()
    await driver.request(
        "POST",
        "/sign-up/email",
        json_body={
            "email": "attacker-update@test.com",
            "password": "password123",
            "name": "Attacker",
        },
    )
    r = await driver.request(
        "POST",
        "/passkey/update-passkey",
        json_body={"id": pk["id"], "name": "hacked"},
    )
    assert r.status >= 400
    unchanged = await adapter.find_one(model="passkey", where=(Where(field="id", value=pk["id"]),))
    assert unchanged["name"] == "original-name"


async def test_should_verify_passkey_authentication_and_return_user() -> None:
    driver, adapter, _ = _build()
    user_id = await _sign_up(driver, email="auth-user@test.com")
    await _seed_passkey(adapter, user_id)

    # generate authenticate options to set the challenge cookie
    await driver.request(
        "GET", "/passkey/generate-authenticate-options", headers={"origin": ORIGIN}
    )

    webauthn_server.verify_authentication_response = lambda **_: VerifiedAuthenticationResponse(
        verified=True, authentication_info=AuthenticationInfo(new_counter=1)
    )

    r = await driver.request(
        "POST",
        "/passkey/verify-authentication",
        headers={"origin": ORIGIN},
        json_body={
            "response": {
                "id": "mockCredentialID",
                "rawId": "mockRawId",
                "response": {
                    "clientDataJSON": "mockClientDataJSON",
                    "authenticatorData": "mockAuthenticatorData",
                    "signature": "mockSignature",
                    "userHandle": "mockUserHandle",
                },
                "type": "public-key",
                "clientExtensionResults": {},
            }
        },
    )
    assert r.status == 200, r.json()
    body = r.json()
    assert body["session"] is not None
    assert body["user"] is not None
    assert body["user"]["id"] == user_id
    assert body["user"]["email"] == "auth-user@test.com"


# ----- expirationTime per-request -------------------------------------------


async def test_should_compute_expiration_time_per_request_registration(monkeypatch) -> None:
    """The verification ``expiresAt`` is computed at request time, not init time."""
    import kernia_passkey.routes as routes_mod

    driver, adapter, _ = _build()
    await _sign_up(driver)

    fixed_now = 10_000_000
    monkeypatch.setattr(routes_mod, "_now", lambda: fixed_now)

    await driver.request("GET", "/passkey/generate-register-options")
    rows = await adapter.find_many(model="verification")
    row = rows[-1]
    assert int(row["expiresAt"]) > fixed_now


async def test_should_compute_expiration_time_per_request_authentication(monkeypatch) -> None:
    import kernia_passkey.routes as routes_mod

    driver, adapter, _ = _build()
    fixed_now = 20_000_000
    monkeypatch.setattr(routes_mod, "_now", lambda: fixed_now)

    await driver.request("GET", "/passkey/generate-authenticate-options")
    rows = await adapter.find_many(model="verification")
    row = rows[-1]
    assert int(row["expiresAt"]) > fixed_now


# ----- schema (unit) ---------------------------------------------------------


def test_passkey_plugin_schema_registers_table() -> None:
    p = passkey()
    assert p.schema is not None
    table_names = {m.name for m in p.schema.tables}
    assert "passkey" in table_names
    model = next(m for m in p.schema.tables if m.name == "passkey")
    field_names = {f.name for f in model.fields}
    assert {"credentialID", "publicKey", "counter", "userId", "aaguid"} <= field_names
