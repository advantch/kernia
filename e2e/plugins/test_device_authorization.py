"""End-to-end: full RFC 8628 device-flow exchange.

Ports `reference/packages/better-auth/src/plugins/device-authorization/
device-authorization.test.ts` 1:1 (names + assertions).

Envelope note: upstream returns OAuth errors as top-level ``{error,
error_description}`` on the response body. The Python error envelope nests plugin
payloads under ``data``, so these tests read ``r.json()["data"]`` via ``_oauth``.
The ``error`` codes and descriptions are identical to upstream.

Not ported: the two ``deviceAuthorizationOptionsSchema.parse`` snapshot tests and
``verificationUri: 123`` validation — those exercise upstream's zod option schema,
which has no analogue in the Python dataclass option model. Time-string parsing
('30m' -> 300s) is instead exercised through the live ``/device/code`` responses.
"""

from __future__ import annotations

import time

import pytest
from kernia.auth import init
from kernia.plugins import device_authorization, email_and_password
from kernia.plugins.device_authorization.routes import parse_ms
from kernia.types.adapter import Where
from kernia.types.init_options import KerniaOptions
from kernia_test_utils import ASGIDriver
from kernia_test_utils.adapter_fixtures import all_adapters_param

GRANT = "urn:ietf:params:oauth:grant-type:device_code"


def _memory():
    from kernia_memory_adapter import memory_adapter

    return memory_adapter()


def _oauth(r) -> dict:
    """Return the OAuth ``{error, error_description}`` payload from an error body."""
    body = r.json()
    return body.get("data", body)


_AUTH_BY_APP: dict[int, object] = {}


def _build(*da_kwargs_plugins) -> ASGIDriver:
    """Build a driver with email/password + a configured device_authorization.

    The backing ``AuthContext`` is registered by the mounted app object so tests can
    fetch it (for direct adapter assertions) via ``_auth_of(driver)``.
    """
    auth = init(
        KerniaOptions(
            database=_memory(),
            secret="device-secret",
            plugins=[email_and_password(), *da_kwargs_plugins],
        )
    )
    app = auth.router.mount()
    _AUTH_BY_APP[id(app)] = auth
    return ASGIDriver(app=app)


async def _sign_in(
    driver: ASGIDriver, email: str = "human@example.com", password: str = "approvepass1"
) -> None:
    r = await driver.request(
        "POST",
        "/sign-up/email",
        json_body={"email": email, "password": password, "name": "human"},
    )
    assert r.status == 200, r.json()


async def _device_code(driver: ASGIDriver, **body) -> dict:
    body.setdefault("client_id", "test-client")
    r = await driver.request("POST", "/device/code", json_body=body)
    assert r.status == 200, r.json()
    return r.json()


async def _token(driver: ASGIDriver, device_code: str, client_id: str = "test-client"):
    return await driver.request(
        "POST",
        "/device/token",
        json_body={"grant_type": GRANT, "device_code": device_code, "client_id": client_id},
    )


async def _make_adapter_with_device_code(adapter_factory) -> object:
    """Build an adapter that also knows about the deviceCode plugin table.

    The shared `all_adapters_param` fixture creates the adapter with core
    models only; we re-materialize the plugin schema for backends that need it.
    """
    adapter = await adapter_factory()
    create_schema = getattr(adapter, "create_schema", None)
    if create_schema is not None:
        from kernia.plugins.device_authorization.plugin import DEVICE_CODE_MODEL

        await create_schema(models=(DEVICE_CODE_MODEL,))
    return adapter


@pytest.mark.parametrize(*all_adapters_param())
async def test_full_device_flow(adapter_factory) -> None:
    adapter = await _make_adapter_with_device_code(adapter_factory)
    auth = init(
        KerniaOptions(
            database=adapter,
            secret="device-secret",
            plugins=[email_and_password(), device_authorization(interval=0)],
        )
    )
    driver = ASGIDriver(app=auth.router.mount())

    # 1. Client requests a device code.
    r = await driver.request(
        "POST",
        "/device/code",
        json_body={"client_id": "cli-app", "scope": "read"},
    )
    assert r.status == 200, r.json()
    payload = r.json()
    device_code = payload["device_code"]
    user_code = payload["user_code"]
    assert payload["verification_uri"].endswith("/device")
    assert user_code in payload["verification_uri_complete"]

    # 2. CLI starts polling — first poll returns authorization_pending.
    r = await driver.request(
        "POST",
        "/device/token",
        json_body={
            "device_code": device_code,
            "client_id": "cli-app",
            "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
        },
    )
    assert r.status == 400, r.json()
    assert r.json()["code"] == "AUTHORIZATION_PENDING"

    # 3. Meanwhile a real user signs in via the browser and approves.
    user_driver = ASGIDriver(app=auth.router.mount())
    await user_driver.request(
        "POST",
        "/sign-up/email",
        json_body={"email": "human@example.com", "password": "approvepass"},
    )
    # GET /device claims the code for the active user.
    r = await user_driver.request("GET", "/device", query=f"user_code={user_code}")
    assert r.status == 200, r.json()
    assert r.json()["status"] == "pending"

    r = await user_driver.request(
        "POST",
        "/device/approve",
        json_body={"user_code": user_code},
    )
    assert r.status == 200, r.json()

    # 4. CLI polls again — now receives the access token (= session token).
    r = await driver.request(
        "POST",
        "/device/token",
        json_body={
            "device_code": device_code,
            "client_id": "cli-app",
            "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
        },
    )
    assert r.status == 200, r.json()
    body = r.json()
    assert body["token_type"] == "Bearer"
    assert isinstance(body["access_token"], str)
    assert body["access_token"]


@pytest.mark.parametrize(*all_adapters_param())
async def test_device_flow_denial(adapter_factory) -> None:
    adapter = await _make_adapter_with_device_code(adapter_factory)
    auth = init(
        KerniaOptions(
            database=adapter,
            secret="s",
            plugins=[email_and_password(), device_authorization(interval=0)],
        )
    )
    driver = ASGIDriver(app=auth.router.mount())

    r = await driver.request("POST", "/device/code", json_body={"client_id": "cli"})
    user_code = r.json()["user_code"]
    device_code = r.json()["device_code"]

    user_driver = ASGIDriver(app=auth.router.mount())
    await user_driver.request(
        "POST",
        "/sign-up/email",
        json_body={"email": "u@example.com", "password": "passpass1"},
    )
    await user_driver.request("GET", "/device", query=f"user_code={user_code}")
    r = await user_driver.request("POST", "/device/deny", json_body={"user_code": user_code})
    assert r.status == 200, r.json()

    r = await driver.request(
        "POST",
        "/device/token",
        json_body={
            "device_code": device_code,
            "client_id": "cli",
            "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
        },
    )
    assert r.status == 400
    assert r.json()["code"] == "ACCESS_DENIED"


# ======================================================================================
# Upstream: input validation (time-string parsing analogue)
# ======================================================================================


def test_parse_ms_time_strings() -> None:
    assert parse_ms("30m") == 1_800_000
    assert parse_ms("5s") == 5_000
    assert parse_ms("1h") == 3_600_000
    assert parse_ms("5min") == 300_000
    assert parse_ms("1m") == 60_000
    assert parse_ms("2s") == 2_000


# ======================================================================================
# Upstream describe: "client validation"
# ======================================================================================


def _client_validated_plugin():
    valid_clients = {"valid-client-1", "valid-client-2"}
    return device_authorization(validate_client=lambda cid: cid in valid_clients)


async def test_should_reject_invalid_client_in_device_code_request() -> None:
    driver = _build(_client_validated_plugin())
    r = await driver.request("POST", "/device/code", json_body={"client_id": "invalid-client"})
    assert r.status == 400
    payload = _oauth(r)
    assert payload["error"] == "invalid_client"
    assert payload["error_description"] == "Invalid client ID"


async def test_should_accept_valid_client_in_device_code_request() -> None:
    driver = _build(_client_validated_plugin())
    r = await driver.request("POST", "/device/code", json_body={"client_id": "valid-client-1"})
    assert r.status == 200
    assert r.json()["device_code"]


async def test_should_reject_invalid_client_in_token_request() -> None:
    driver = _build(_client_validated_plugin())
    code = await _device_code(driver, client_id="valid-client-1")
    r = await _token(driver, code["device_code"], client_id="invalid-client")
    assert r.status == 400
    payload = _oauth(r)
    assert payload["error"] == "invalid_grant"
    assert payload["error_description"] == "Invalid client ID"


async def test_should_reject_mismatched_client_id_in_token_request() -> None:
    driver = _build(_client_validated_plugin())
    code = await _device_code(driver, client_id="valid-client-1")
    r = await _token(driver, code["device_code"], client_id="valid-client-2")
    assert r.status == 400
    payload = _oauth(r)
    assert payload["error"] == "invalid_grant"
    assert payload["error_description"] == "Client ID mismatch"


# ======================================================================================
# Upstream describe: "device authorization flow" -> "device code request"
# ======================================================================================


def _flow_plugin():
    return device_authorization(expires_in="5min", interval="2s")


async def test_should_generate_device_and_user_codes() -> None:
    driver = _build(_flow_plugin())
    resp = await _device_code(driver)
    assert resp["device_code"]
    assert resp["user_code"]
    assert "/device" in resp["verification_uri"]
    assert "/device" in resp["verification_uri_complete"]
    assert f"user_code={resp['user_code']}" in resp["verification_uri_complete"]
    assert resp["expires_in"] == 300
    assert resp["interval"] == 2
    import re

    assert re.match(r"^[A-Z0-9]{8}$", resp["user_code"])


async def test_should_support_custom_client_id_and_scope() -> None:
    driver = _build(_flow_plugin())
    resp = await _device_code(driver, scope="read write")
    assert resp["device_code"]
    assert resp["user_code"]


# ======================================================================================
# Upstream describe: "device token polling"
# ======================================================================================


async def test_should_return_authorization_pending_when_not_approved() -> None:
    driver = _build(_flow_plugin())
    code = await _device_code(driver)
    r = await _token(driver, code["device_code"])
    assert r.status == 400
    payload = _oauth(r)
    assert payload["error"] == "authorization_pending"
    assert payload["error_description"] == "Authorization pending"


async def test_should_return_expired_token_for_expired_device_codes() -> None:
    driver = _build(_flow_plugin())
    code = await _device_code(driver)

    # Force the row to be expired (upstream advances fake timers).
    auth_ctx = _auth_of(driver)
    rows = await auth_ctx.adapter.find_many(model="deviceCode", where=())
    for row in rows:
        await auth_ctx.adapter.update(
            model="deviceCode",
            where=(Where(field="id", value=row["id"]),),
            update={"expiresAt": int(time.time()) - 1},
        )

    r = await _token(driver, code["device_code"])
    assert r.status == 400
    payload = _oauth(r)
    assert payload["error"] == "expired_token"
    assert payload["error_description"] == "Device code has expired"


async def test_should_return_error_for_invalid_device_code() -> None:
    driver = _build(_flow_plugin())
    r = await _token(driver, "invalid-code")
    assert r.status == 400
    payload = _oauth(r)
    assert payload["error"] == "invalid_grant"
    assert payload["error_description"] == "Invalid device code"


# ======================================================================================
# Upstream describe: "device verification"
# ======================================================================================


async def test_should_verify_valid_user_code() -> None:
    driver = _build(_flow_plugin())
    code = await _device_code(driver)
    r = await driver.request("GET", "/device", query=f"user_code={code['user_code']}")
    assert r.status == 200
    assert r.json()["user_code"] == code["user_code"]
    assert r.json()["status"] == "pending"


async def test_should_handle_invalid_user_code() -> None:
    driver = _build(_flow_plugin())
    r = await driver.request("GET", "/device", query="user_code=INVALID")
    assert r.status == 400
    payload = _oauth(r)
    assert payload["error"] == "invalid_request"
    assert payload["error_description"] == "Invalid user code"


# ======================================================================================
# Upstream describe: "device approval flow"
# ======================================================================================


async def test_should_approve_device_and_create_session() -> None:
    driver = _build(_flow_plugin())
    await _sign_in(driver)
    code = await _device_code(driver)

    await driver.request("GET", "/device", query=f"user_code={code['user_code']}")
    approve = await driver.request(
        "POST", "/device/approve", json_body={"user_code": code["user_code"]}
    )
    assert approve.status == 200, approve.json()
    assert approve.json()["success"] is True

    r = await _token(driver, code["device_code"])
    assert r.status == 200, r.json()
    body = r.json()
    assert body["access_token"]
    assert body["token_type"] == "Bearer"
    assert body["expires_in"] > 0
    assert "scope" in body


async def test_should_deny_device_authorization() -> None:
    driver = _build(_flow_plugin())
    await _sign_in(driver)
    code = await _device_code(driver)

    await driver.request("GET", "/device", query=f"user_code={code['user_code']}")
    deny = await driver.request("POST", "/device/deny", json_body={"user_code": code["user_code"]})
    assert deny.status == 200, deny.json()
    assert deny.json()["success"] is True

    r = await _token(driver, code["device_code"])
    assert r.status == 400
    payload = _oauth(r)
    assert payload["error"] == "access_denied"
    assert payload["error_description"] == "Access denied"


async def test_should_require_authentication_for_approval() -> None:
    driver = _build(_flow_plugin())
    code = await _device_code(driver)
    r = await driver.request("POST", "/device/approve", json_body={"user_code": code["user_code"]})
    assert r.status == 401
    payload = _oauth(r)
    assert payload["error"] == "unauthorized"
    assert payload["error_description"] == "Authentication required"


async def test_should_enforce_rate_limiting_with_slow_down_error() -> None:
    driver = _build(_flow_plugin())
    code = await _device_code(driver)
    # First poll establishes lastPolledAt.
    await _token(driver, code["device_code"])
    # Immediate second poll is too frequent (interval 2s).
    r = await _token(driver, code["device_code"])
    assert r.status == 400
    payload = _oauth(r)
    assert payload["error"] == "slow_down"
    assert payload["error_description"] == "Polling too frequently"


# ======================================================================================
# Upstream describe: "edge cases"
# ======================================================================================


async def test_should_not_allow_approving_already_processed_device_code() -> None:
    driver = _build(_flow_plugin())
    await _sign_in(driver)
    code = await _device_code(driver)
    await driver.request("GET", "/device", query=f"user_code={code['user_code']}")
    await driver.request("POST", "/device/approve", json_body={"user_code": code["user_code"]})
    r = await driver.request("POST", "/device/approve", json_body={"user_code": code["user_code"]})
    assert r.status == 400
    payload = _oauth(r)
    assert payload["error"] == "invalid_request"
    assert payload["error_description"] == "Device code already processed"


async def test_should_handle_user_code_without_dashes() -> None:
    driver = _build(_flow_plugin())
    code = await _device_code(driver)
    clean = code["user_code"].replace("-", "")
    r = await driver.request("GET", "/device", query=f"user_code={clean}")
    assert r.status == 200
    assert r.json()["status"] == "pending"


async def test_should_store_and_use_scope_from_device_code_request() -> None:
    driver = _build(_flow_plugin())
    await _sign_in(driver)
    code = await _device_code(driver, scope="read write profile")
    await driver.request("GET", "/device", query=f"user_code={code['user_code']}")
    await driver.request("POST", "/device/approve", json_body={"user_code": code["user_code"]})
    r = await _token(driver, code["device_code"])
    assert r.status == 200, r.json()
    assert r.json()["scope"] == "read write profile"


async def test_should_require_authentication_for_deny() -> None:
    driver = _build(_flow_plugin())
    code = await _device_code(driver)
    r = await driver.request("POST", "/device/deny", json_body={"user_code": code["user_code"]})
    assert r.status == 401
    payload = _oauth(r)
    assert payload["error"] == "unauthorized"
    assert payload["error_description"] == "Authentication required"


async def test_should_allow_first_user_to_approve_but_prevent_re_approval() -> None:
    driver = _build(_flow_plugin())
    await _sign_in(driver)
    code = await _device_code(driver)
    await driver.request("GET", "/device", query=f"user_code={code['user_code']}")

    approve = await driver.request(
        "POST", "/device/approve", json_body={"user_code": code["user_code"]}
    )
    assert approve.json()["success"] is True

    auth_ctx = _auth_of(driver)
    clean = code["user_code"].replace("-", "")
    row = await auth_ctx.adapter.find_one(
        model="deviceCode", where=(Where(field="userCode", value=clean),)
    )
    assert row["status"] == "approved"
    assert row["userId"]

    r = await driver.request("POST", "/device/approve", json_body={"user_code": code["user_code"]})
    assert r.status == 400
    payload = _oauth(r)
    assert payload["error"] == "invalid_request"
    assert payload["error_description"] == "Device code already processed"


# ======================================================================================
# Upstream describe: "device authorization ownership gate" (GHSA-cq3f-vc6p-68fh)
# ======================================================================================


async def test_rejects_approve_from_session_that_did_not_claim_pending_code() -> None:
    driver = _build(_flow_plugin())
    attacker = ASGIDriver(app=driver.app)  # share the same auth/adapter
    await _sign_in(attacker, email="attacker@example.test", password="attackerpass1")

    code = await _device_code(driver)  # no claim happens
    assert code["device_code"]
    assert code["user_code"]

    r = await attacker.request(
        "POST", "/device/approve", json_body={"user_code": code["user_code"]}
    )
    assert r.status == 400
    assert _oauth(r)["error"] == "invalid_request"

    auth_ctx = _auth_of(driver)
    row = await auth_ctx.adapter.find_one(
        model="deviceCode", where=(Where(field="userCode", value=code["user_code"]),)
    )
    assert row["status"] == "pending"
    assert not row["userId"]

    r = await _token(driver, code["device_code"])
    assert r.status == 400
    assert _oauth(r)["error"] == "authorization_pending"


async def test_rejects_deny_from_session_that_did_not_claim_pending_code() -> None:
    driver = _build(_flow_plugin())
    attacker = ASGIDriver(app=driver.app)
    await _sign_in(attacker, email="attacker@example.test", password="attackerpass1")

    code = await _device_code(driver)
    r = await attacker.request("POST", "/device/deny", json_body={"user_code": code["user_code"]})
    assert r.status == 400
    assert _oauth(r)["error"] == "invalid_request"

    auth_ctx = _auth_of(driver)
    row = await auth_ctx.adapter.find_one(
        model="deviceCode", where=(Where(field="userCode", value=code["user_code"]),)
    )
    assert row["status"] == "pending"
    assert not row["userId"]


async def test_allows_approve_when_same_session_called_verify_first() -> None:
    driver = _build(_flow_plugin())
    await _sign_in(driver, email="legit@example.test", password="legitpass1")
    code = await _device_code(driver)
    await driver.request("GET", "/device", query=f"user_code={code['user_code']}")
    r = await driver.request("POST", "/device/approve", json_body={"user_code": code["user_code"]})
    assert r.status == 200, r.json()
    assert r.json()["success"] is True


async def test_rejects_approve_from_different_user_after_another_claimed() -> None:
    driver = _build(_flow_plugin())
    await _sign_in(driver, email="claimer@example.test", password="claimerpass1")
    attacker = ASGIDriver(app=driver.app)
    await _sign_in(attacker, email="attacker@example.test", password="attackerpass1")

    code = await _device_code(driver)
    await driver.request("GET", "/device", query=f"user_code={code['user_code']}")

    r = await attacker.request(
        "POST", "/device/approve", json_body={"user_code": code["user_code"]}
    )
    assert r.status == 403
    assert _oauth(r)["error"] == "access_denied"

    r = await attacker.request("POST", "/device/deny", json_body={"user_code": code["user_code"]})
    assert r.status == 403
    assert _oauth(r)["error"] == "access_denied"


async def test_does_not_overwrite_a_device_code_claimed_after_verify_reads_it() -> None:
    # Replicates the upstream concurrent-claim test: a competing writer claims the
    # code for `concurrent_owner` between verify's read and its guarded update. The
    # guard (`userId IS NULL`) must make the racer's claim a no-op.
    base = _memory()

    state = {"simulate": False, "owner_id": None}
    original_update = base.update

    async def racing_update(*, model, where, update):
        if (
            state["simulate"]
            and state["owner_id"]
            and model == "deviceCode"
            and update.get("userId")
        ):
            state["simulate"] = False
            dc_id = next((w.value for w in where if w.field == "id"), None)
            if isinstance(dc_id, str):
                await original_update(
                    model="deviceCode",
                    where=(Where(field="id", value=dc_id),),
                    update={"userId": state["owner_id"]},
                )
        return await original_update(model=model, where=where, update=update)

    base.update = racing_update  # type: ignore[method-assign]

    auth = init(
        KerniaOptions(
            database=base,
            secret="device-secret",
            plugins=[email_and_password(), _flow_plugin()],
        )
    )
    driver = ASGIDriver(app=auth.router.mount())

    owner = ASGIDriver(app=auth.router.mount())
    await _sign_in(owner, email="concurrent-owner@example.test", password="ownerpass1")
    owner_row = await auth.context.adapter.find_one(
        model="user", where=(Where(field="email", value="concurrent-owner@example.test"),)
    )
    state["owner_id"] = owner_row["id"]

    racer = ASGIDriver(app=auth.router.mount())
    await _sign_in(racer, email="racer@example.test", password="racerpass1")
    racer_row = await auth.context.adapter.find_one(
        model="user", where=(Where(field="email", value="racer@example.test"),)
    )

    code = await _device_code(driver)

    state["simulate"] = True
    await racer.request("GET", "/device", query=f"user_code={code['user_code']}")
    # The concurrent claim must have actually fired during verify's update.
    assert state["simulate"] is False

    row = await auth.context.adapter.find_one(
        model="deviceCode", where=(Where(field="userCode", value=code["user_code"]),)
    )
    assert row["userId"] == state["owner_id"]
    assert row["userId"] != racer_row["id"]
    assert row["status"] == "pending"


# ======================================================================================
# Upstream describe: "device authorization with custom options"
# ======================================================================================


async def test_should_correctly_store_interval_as_milliseconds() -> None:
    driver = _build(device_authorization(interval="5s"))
    resp = await _device_code(driver)
    assert resp["interval"] == 5

    auth_ctx = _auth_of(driver)
    row = await auth_ctx.adapter.find_one(
        model="deviceCode",
        where=(Where(field="deviceCode", value=resp["device_code"]),),
    )
    assert row["pollingInterval"] == 5000
    assert isinstance(row["pollingInterval"], int)


async def test_should_use_custom_code_generators() -> None:
    driver = _build(
        device_authorization(
            generate_device_code=lambda: "custom-device-code-12345",
            generate_user_code=lambda: "CUSTOM12",
        )
    )
    resp = await _device_code(driver)
    assert resp["device_code"] == "custom-device-code-12345"
    assert resp["user_code"] == "CUSTOM12"


async def test_should_respect_custom_expiration_time() -> None:
    driver = _build(device_authorization(expires_in="1min"))
    resp = await _device_code(driver)
    assert resp["expires_in"] == 60


# ======================================================================================
# Upstream describe: "verificationUri option"
# ======================================================================================


async def test_should_return_default_device_verification_uris() -> None:
    driver = _build(device_authorization())
    resp = await _device_code(driver)
    assert "/device" in resp["verification_uri"]
    assert "/device" in resp["verification_uri_complete"]
    assert f"user_code={resp['user_code']}" in resp["verification_uri_complete"]


async def test_should_use_custom_relative_path_for_verification_uri() -> None:
    driver = _build(device_authorization(verification_uri="/auth/device-verify"))
    resp = await _device_code(driver)
    assert "/auth/device-verify" in resp["verification_uri"]
    assert "/auth/device-verify" in resp["verification_uri_complete"]
    assert f"user_code={resp['user_code']}" in resp["verification_uri_complete"]


async def test_should_use_absolute_url_for_verification_uri() -> None:
    custom = "https://myapp.com/device"
    driver = _build(device_authorization(verification_uri=custom))
    resp = await _device_code(driver)
    assert resp["verification_uri"] == custom
    assert resp["verification_uri_complete"] == f"{custom}?user_code={resp['user_code']}"


async def test_should_encode_user_code_in_verification_uri_complete() -> None:
    driver = _build(
        device_authorization(verification_uri="/device", generate_user_code=lambda: "ABC-123")
    )
    resp = await _device_code(driver)
    assert "user_code=ABC-123" in resp["verification_uri_complete"]


async def test_should_support_verification_uri_with_existing_query_params() -> None:
    driver = _build(device_authorization(verification_uri="/device?lang=en"))
    resp = await _device_code(driver)
    assert "lang=en" in resp["verification_uri"]
    assert "lang=en" in resp["verification_uri_complete"]
    assert f"user_code={resp['user_code']}" in resp["verification_uri_complete"]


def _auth_of(driver: ASGIDriver):
    """Return the auth context behind an ASGIDriver (for direct adapter assertions)."""
    return _AUTH_BY_APP[id(driver.app)].context
