"""Integration tests for the SIWE (Sign-In With Ethereum) plugin.

Generates a real key pair via `eth_account`, signs an EIP-4361-style message
client-side, then posts it to `/siwe/verify` and asserts a session is issued.
"""

from __future__ import annotations

import pytest

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
    r = await driver.request(
        "GET", "/siwe/nonce", query=f"address={address}"
    )
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
    assert r.json()["code"] == "INVALID_SIWE_SIGNATURE"


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
