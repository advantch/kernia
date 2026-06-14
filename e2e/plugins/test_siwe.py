"""Integration tests for the SIWE (Sign-In With Ethereum) plugin.

Generates a real key pair via `eth_account`, signs an EIP-4361-style message
client-side, then posts it to `/siwe/verify` and asserts a session is issued.
"""

from __future__ import annotations

from kernia.auth import init
from kernia.plugins.email_password import email_and_password
from kernia.plugins.siwe import siwe
from kernia.types.init_options import KerniaOptions
from kernia_memory_adapter import memory_adapter
from kernia_test_utils import ASGIDriver


def _build() -> ASGIDriver:
    auth = init(
        KerniaOptions(
            database=memory_adapter(),
            secret="test-secret-key",
            plugins=[email_and_password(), siwe()],
        )
    )
    return ASGIDriver(app=auth.router.mount())


def _siwe_message(domain: str, address: str, nonce: str) -> str:
    return (
        f"{domain} wants you to sign in with your Ethereum account:\n"
        f"{address}\n\n"
        "Sign-in for tests.\n\n"
        f"URI: https://{domain}\n"
        "Version: 1\n"
        "Chain ID: 1\n"
        f"Nonce: {nonce}\n"
        "Issued At: 2026-05-16T00:00:00Z\n"
    )


async def test_siwe_full_round_trip() -> None:
    from eth_account import Account
    from eth_account.messages import encode_defunct

    acct = Account.create()
    address = acct.address  # checksummed

    driver = _build()

    # 1. Get nonce.
    r = await driver.request("GET", "/siwe/nonce", query=f"address={address}")
    assert r.status == 200, r.json()
    nonce = r.json()["nonce"]

    # 2. Build + sign message client-side.
    msg = _siwe_message("example.com", address, nonce)
    signed = acct.sign_message(encode_defunct(text=msg))

    # 3. Verify.
    r = await driver.request(
        "POST",
        "/siwe/verify",
        json_body={
            "message": msg,
            "signature": signed.signature.hex(),
            "address": address,
        },
    )
    assert r.status == 200, r.json()
    body = r.json()
    assert body["success"] is True
    assert body["user"]["walletAddress"] == address

    # 4. Session cookie issued — get-session works.
    r = await driver.request("GET", "/get-session")
    assert r.status == 200
    assert r.json()["user"]["walletAddress"] == address


async def test_siwe_bad_signature_rejected() -> None:
    from eth_account import Account

    acct = Account.create()
    other = Account.create()
    driver = _build()

    r = await driver.request("GET", "/siwe/nonce", query=f"address={acct.address}")
    nonce = r.json()["nonce"]
    msg = _siwe_message("example.com", acct.address, nonce)

    # Sign with the wrong key — verifier must reject.
    from eth_account.messages import encode_defunct

    signed = other.sign_message(encode_defunct(text=msg))
    r = await driver.request(
        "POST",
        "/siwe/verify",
        json_body={
            "message": msg,
            "signature": signed.signature.hex(),
            "address": acct.address,
        },
    )
    assert r.status == 401
    # Upstream returns a generic UNAUTHORIZED for a signature that doesn't verify.
    assert r.json()["code"] == "UNAUTHORIZED"


async def test_siwe_replay_nonce_rejected() -> None:
    from eth_account import Account
    from eth_account.messages import encode_defunct

    acct = Account.create()
    driver = _build()

    r = await driver.request("GET", "/siwe/nonce", query=f"address={acct.address}")
    nonce = r.json()["nonce"]
    msg = _siwe_message("example.com", acct.address, nonce)
    signed = acct.sign_message(encode_defunct(text=msg))

    r1 = await driver.request(
        "POST",
        "/siwe/verify",
        json_body={
            "message": msg,
            "signature": signed.signature.hex(),
            "address": acct.address,
        },
    )
    assert r1.status == 200

    # Replay with the same nonce — must be rejected because nonce was consumed.
    driver.cookies.clear()
    r2 = await driver.request(
        "POST",
        "/siwe/verify",
        json_body={
            "message": msg,
            "signature": signed.signature.hex(),
            "address": acct.address,
        },
    )
    assert r2.status == 401
    assert r2.json()["code"] == "UNAUTHORIZED_INVALID_OR_EXPIRED_NONCE"


# ======================================================================================
# Upstream-ported suite (reference/.../siwe/siwe.test.ts).
#
# Like upstream, these use stubbed `get_nonce` / `verify_message` so no real
# wallet crypto is needed: `verify_message` accepts exactly
# (message="valid_message", signature="valid_signature").
# ======================================================================================

import re  # noqa: E402

from kernia.types.adapter import Where  # noqa: E402

WALLET = "0x000000000000000000000000000000000000dEaD"
DOMAIN = "example.com"


async def _fixed_nonce() -> str:
    return "A1b2C3d4E5f6G7h8J"


async def _stub_verify(args) -> bool:
    return args["signature"] == "valid_signature" and args["message"] == "valid_message"


def _stub_auth(**siwe_kwargs):
    auth = init(
        KerniaOptions(
            database=memory_adapter(),
            secret="test-secret-key",
            plugins=[
                siwe(
                    domain=DOMAIN,
                    get_nonce=_fixed_nonce,
                    verify_message=_stub_verify,
                    **siwe_kwargs,
                )
            ],
            advanced={"disable_csrf_check": True},
        )
    )
    return auth, ASGIDriver(app=auth.router.mount())


async def _nonce(driver: ASGIDriver, *, wallet=WALLET, chain_id=1):
    return await driver.request(
        "POST", "/siwe/nonce", json_body={"walletAddress": wallet, "chainId": chain_id}
    )


async def test_generate_valid_nonce() -> None:
    _, driver = _stub_auth()
    r = await driver.request(
        "POST", "/siwe/nonce", json_body={"walletAddress": WALLET, "chainId": 1}
    )
    assert r.status == 200, r.json()
    assert re.match(r"^[a-zA-Z0-9]{17}$", r.json()["nonce"])


async def test_generate_valid_nonce_default_chain_id() -> None:
    _, driver = _stub_auth()
    r = await driver.request("POST", "/siwe/nonce", json_body={"walletAddress": WALLET})
    assert r.status == 200, r.json()
    assert re.match(r"^[a-zA-Z0-9]{17}$", r.json()["nonce"])


async def test_get_nonce_alias_with_address_input() -> None:
    _, driver = _stub_auth()
    r = await driver.request("POST", "/siwe/get-nonce", json_body={"address": WALLET, "chainId": 1})
    assert r.status == 200, r.json()
    assert r.json()["nonce"] == "A1b2C3d4E5f6G7h8J"


async def test_reject_verification_when_nonce_missing() -> None:
    _, driver = _stub_auth()
    r = await driver.request(
        "POST",
        "/siwe/verify",
        json_body={
            "message": "valid_message",
            "signature": "valid_signature",
            "walletAddress": WALLET,
            "chainId": 1,
        },
    )
    assert r.status == 401
    assert r.json()["code"] == "UNAUTHORIZED_INVALID_OR_EXPIRED_NONCE"
    assert "nonce" in r.json()["message"].lower()


async def test_reject_invalid_public_key() -> None:
    _, driver = _stub_auth()
    r = await driver.request("POST", "/siwe/nonce", json_body={"walletAddress": "invalid"})
    assert r.status == 400
    assert r.json()["message"] == (
        "[body.walletAddress] Invalid string: must match pattern "
        "/^0[xX][a-fA-F0-9]{40}$/i; [body.walletAddress] Too small: expected "
        "string to have >=42 characters"
    )


async def test_reject_invalid_signature() -> None:
    _, driver = _stub_auth()
    await _nonce(driver)
    r = await driver.request(
        "POST",
        "/siwe/verify",
        json_body={
            "message": "Sign in with Ethereum.",
            "signature": "invalid_signature",
            "walletAddress": WALLET,
        },
    )
    assert r.status == 401


async def test_reject_invalid_wallet_address_format() -> None:
    _, driver = _stub_auth()
    r = await driver.request("POST", "/siwe/nonce", json_body={"walletAddress": "not_a_valid_key"})
    assert r.status == 400


async def test_reject_invalid_message() -> None:
    _, driver = _stub_auth()
    await _nonce(driver)
    r = await driver.request(
        "POST",
        "/siwe/verify",
        json_body={
            "message": "invalid_message",
            "signature": "valid_signature",
            "walletAddress": WALLET,
        },
    )
    assert r.status == 401


async def test_reject_no_email_when_anonymous_false() -> None:
    _, driver = _stub_auth(anonymous=False)
    r = await driver.request(
        "POST",
        "/siwe/verify",
        json_body={
            "message": "valid_message",
            "signature": "valid_signature",
            "walletAddress": WALLET,
        },
    )
    assert r.status == 400
    assert r.json()["message"] == (
        "[body.email] Email is required when the anonymous plugin option is disabled."
    )


async def test_accept_email_when_anonymous_false() -> None:
    _, driver = _stub_auth(anonymous=False)
    await _nonce(driver)
    r = await driver.request(
        "POST",
        "/siwe/verify",
        json_body={
            "message": "valid_message",
            "signature": "valid_signature",
            "walletAddress": WALLET,
            "chainId": 1,
            "email": "user@example.com",
        },
    )
    assert r.status == 200, r.json()
    assert r.json()["success"] is True


async def test_reject_invalid_email_format_when_anonymous_false() -> None:
    _, driver = _stub_auth(anonymous=False)
    r = await driver.request(
        "POST",
        "/siwe/verify",
        json_body={
            "message": "valid_message",
            "signature": "valid_signature",
            "walletAddress": WALLET,
            "email": "not-an-email",
        },
    )
    assert r.status == 400
    assert r.json()["message"] == "[body.email] Invalid email address"


async def test_reject_empty_string_email_when_anonymous_false() -> None:
    _, driver = _stub_auth(anonymous=False)
    await _nonce(driver)
    r = await driver.request(
        "POST",
        "/siwe/verify",
        json_body={
            "message": "valid_message",
            "signature": "valid_signature",
            "walletAddress": WALLET,
            "chainId": 1,
            "email": "",
        },
    )
    assert r.status == 400
    assert r.json()["message"] == (
        "[body.email] Invalid email address; [body.email] Email is required "
        "when the anonymous plugin option is disabled."
    )


async def test_allow_no_email_when_anonymous_true() -> None:
    _, driver = _stub_auth()
    await _nonce(driver)
    r = await driver.request(
        "POST",
        "/siwe/verify",
        json_body={
            "message": "valid_message",
            "signature": "valid_signature",
            "walletAddress": WALLET,
            "chainId": 1,
        },
    )
    assert r.status == 200, r.json()
    assert r.json()["success"] is True


async def test_no_nonce_reuse() -> None:
    _, driver = _stub_auth()
    await _nonce(driver)
    first = await driver.request(
        "POST",
        "/siwe/verify",
        json_body={
            "message": "valid_message",
            "signature": "valid_signature",
            "walletAddress": WALLET,
            "chainId": 1,
        },
    )
    assert first.status == 200
    assert first.json()["success"] is True

    second = await driver.request(
        "POST",
        "/siwe/verify",
        json_body={
            "message": "valid_message",
            "signature": "valid_signature",
            "walletAddress": WALLET,
            "chainId": 1,
        },
    )
    assert second.status == 401
    assert second.json()["code"] == "UNAUTHORIZED_INVALID_OR_EXPIRED_NONCE"


async def test_store_and_return_wallet_address_in_checksum_format() -> None:
    auth, driver = _stub_auth()
    await driver.request(
        "POST", "/siwe/nonce", json_body={"walletAddress": WALLET.lower(), "chainId": 1}
    )
    r = await driver.request(
        "POST",
        "/siwe/verify",
        json_body={
            "message": "valid_message",
            "signature": "valid_signature",
            "walletAddress": WALLET.lower(),
            "chainId": 1,
        },
    )
    assert r.json()["success"] is True

    rows = await auth.context.adapter.find_many(
        model="walletAddress", where=(Where(field="address", value=WALLET),)
    )
    assert len(rows) == 1
    assert rows[0]["address"] == WALLET  # checksummed

    await driver.request(
        "POST", "/siwe/nonce", json_body={"walletAddress": WALLET.upper(), "chainId": 1}
    )
    r2 = await driver.request(
        "POST",
        "/siwe/verify",
        json_body={
            "message": "valid_message",
            "signature": "valid_signature",
            "walletAddress": WALLET.upper(),
            "chainId": 1,
        },
    )
    assert r2.json()["success"] is True
    rows_after = await auth.context.adapter.find_many(
        model="walletAddress", where=(Where(field="address", value=WALLET),)
    )
    assert len(rows_after) == 1


async def test_reject_duplicate_wallet_address_entries() -> None:
    auth, driver = _stub_auth()
    await _nonce(driver)
    first = await driver.request(
        "POST",
        "/siwe/verify",
        json_body={
            "message": "valid_message",
            "signature": "valid_signature",
            "walletAddress": WALLET,
            "chainId": 1,
        },
    )
    assert first.json()["success"] is True

    rows = await auth.context.adapter.find_many(
        model="walletAddress",
        where=(Where(field="address", value=WALLET), Where(field="chainId", value=1)),
    )
    assert len(rows) == 1
    assert rows[0]["isPrimary"] is True

    await _nonce(driver)
    second = await driver.request(
        "POST",
        "/siwe/verify",
        json_body={
            "message": "valid_message",
            "signature": "valid_signature",
            "walletAddress": WALLET,
            "chainId": 1,
        },
    )
    assert second.json()["success"] is True
    assert second.json()["user"]["id"] == first.json()["user"]["id"]

    rows_after = await auth.context.adapter.find_many(
        model="walletAddress",
        where=(Where(field="address", value=WALLET), Where(field="chainId", value=1)),
    )
    assert len(rows_after) == 1


async def test_same_address_different_chains_same_user() -> None:
    auth, driver = _stub_auth()
    await _nonce(driver, chain_id=1)
    eth = await driver.request(
        "POST",
        "/siwe/verify",
        json_body={
            "message": "valid_message",
            "signature": "valid_signature",
            "walletAddress": WALLET,
            "chainId": 1,
        },
    )
    assert eth.json()["success"] is True

    await _nonce(driver, chain_id=137)
    poly = await driver.request(
        "POST",
        "/siwe/verify",
        json_body={
            "message": "valid_message",
            "signature": "valid_signature",
            "walletAddress": WALLET,
            "chainId": 137,
        },
    )
    assert poly.json()["success"] is True
    assert poly.json()["user"]["id"] == eth.json()["user"]["id"]

    rows = await auth.context.adapter.find_many(
        model="walletAddress", where=(Where(field="address", value=WALLET),)
    )
    assert len(rows) == 2
    eth_row = next(r for r in rows if r["chainId"] == 1)
    poly_row = next(r for r in rows if r["chainId"] == 137)
    assert eth_row["isPrimary"] is True
    assert poly_row["isPrimary"] is False
    assert eth_row["userId"] == poly_row["userId"]
