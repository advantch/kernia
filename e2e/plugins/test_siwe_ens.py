"""SIWE plugin + ENS reverse-lookup integration.

We inject a fake ENS resolver into the plugin (no live RPC). The test confirms:
  - on first sign-in the resolved name is persisted to user.ensName
  - user.name defaults to the ENS name when present
  - if the resolver fails (returns None), sign-in still works and ensName=None
  - on repeat sign-in, a stale ensName is refreshed
"""

from __future__ import annotations

import asyncio

import pytest
from kernia.auth import init
from kernia.plugins.siwe import siwe
from kernia.types.adapter import Where
from kernia.types.init_options import KerniaOptions
from kernia_memory_adapter import memory_adapter
from kernia_test_utils import ASGIDriver


def _make_resolver(table: dict[str, str | None]):
    async def _resolve(address: str) -> str | None:
        return table.get(address.lower())

    return _resolve


async def _signed_in(driver: ASGIDriver, *, address: str, ens: bool = False) -> dict:
    """Drive the SIWE flow through the public endpoints with a real signature."""

    # 1. Nonce
    r = await driver.request("GET", "/siwe/nonce", query=f"address={address}")
    assert r.status == 200, r.json()
    nonce = r.json()["nonce"]

    # 2. Build EIP-4361 message and sign it with the private key
    address_cs = address  # caller already passes checksummed
    msg = (
        "test.local wants you to sign in with your Ethereum account:\n"
        f"{address_cs}\n\n"
        "Sign in to test\n\n"
        "URI: https://test.local\n"
        "Version: 1\n"
        "Chain ID: 1\n"
        f"Nonce: {nonce}\n"
        "Issued At: 2025-01-01T00:00:00Z"
    )
    return {"message": msg}


@pytest.fixture
def signing_key():
    from eth_account import Account

    return Account.create()


@pytest.mark.asyncio
async def test_ens_name_persisted_on_first_sign_in(signing_key) -> None:
    from eth_account.messages import encode_defunct

    addr = signing_key.address
    resolver_table: dict[str, str | None] = {addr.lower(): "alice.eth"}
    auth = init(
        KerniaOptions(
            database=memory_adapter(),
            secret="s",
            plugins=[siwe(enable_ens=True, ens_resolver=_make_resolver(resolver_table))],
        )
    )
    await asyncio.sleep(0)
    driver = ASGIDriver(app=auth.router.mount())

    # Get nonce
    r = await driver.request("GET", "/siwe/nonce", query=f"address={addr}")
    nonce = r.json()["nonce"]
    msg = (
        "test.local wants you to sign in with your Ethereum account:\n"
        f"{addr}\n\n"
        "Sign in to test\n\n"
        "URI: https://test.local\n"
        "Version: 1\n"
        "Chain ID: 1\n"
        f"Nonce: {nonce}\n"
        "Issued At: 2025-01-01T00:00:00Z"
    )
    signed = signing_key.sign_message(encode_defunct(text=msg))

    r = await driver.request(
        "POST",
        "/siwe/verify",
        json_body={"message": msg, "signature": signed.signature.hex(), "address": addr},
    )
    assert r.status == 200, r.json()
    user = r.json()["user"]
    assert user["ensName"] == "alice.eth"
    # ensName takes precedence over the raw address for the display name
    assert user["name"] == "alice.eth"


@pytest.mark.asyncio
async def test_sign_in_works_when_resolver_returns_none(signing_key) -> None:
    from eth_account.messages import encode_defunct

    addr = signing_key.address
    # Resolver always returns None
    auth = init(
        KerniaOptions(
            database=memory_adapter(),
            secret="s",
            plugins=[siwe(enable_ens=True, ens_resolver=_make_resolver({}))],
        )
    )
    await asyncio.sleep(0)
    driver = ASGIDriver(app=auth.router.mount())

    r = await driver.request("GET", "/siwe/nonce", query=f"address={addr}")
    nonce = r.json()["nonce"]
    msg = (
        "test.local wants you to sign in with your Ethereum account:\n"
        f"{addr}\n\n"
        "Sign in to test\n\n"
        "URI: https://test.local\n"
        "Version: 1\n"
        "Chain ID: 1\n"
        f"Nonce: {nonce}\n"
        "Issued At: 2025-01-01T00:00:00Z"
    )
    signed = signing_key.sign_message(encode_defunct(text=msg))

    r = await driver.request(
        "POST",
        "/siwe/verify",
        json_body={"message": msg, "signature": signed.signature.hex(), "address": addr},
    )
    assert r.status == 200
    assert r.json()["user"]["ensName"] is None
    # name falls back to the address when no ENS
    assert r.json()["user"]["name"] == addr


@pytest.mark.asyncio
async def test_ens_name_refreshed_on_repeat_sign_in(signing_key) -> None:
    from eth_account.messages import encode_defunct

    addr = signing_key.address
    table: dict[str, str | None] = {addr.lower(): "old.eth"}
    auth = init(
        KerniaOptions(
            database=memory_adapter(),
            secret="s",
            plugins=[siwe(enable_ens=True, ens_resolver=_make_resolver(table))],
        )
    )
    await asyncio.sleep(0)

    async def _sign_in(driver: ASGIDriver) -> dict:
        r = await driver.request("GET", "/siwe/nonce", query=f"address={addr}")
        nonce = r.json()["nonce"]
        msg = (
            "test.local wants you to sign in with your Ethereum account:\n"
            f"{addr}\n\n"
            "Sign in to test\n\n"
            "URI: https://test.local\n"
            "Version: 1\n"
            "Chain ID: 1\n"
            f"Nonce: {nonce}\n"
            "Issued At: 2025-01-01T00:00:00Z"
        )
        signed = signing_key.sign_message(encode_defunct(text=msg))
        r = await driver.request(
            "POST",
            "/siwe/verify",
            json_body={"message": msg, "signature": signed.signature.hex(), "address": addr},
        )
        assert r.status == 200, r.json()
        return r.json()["user"]

    d1 = ASGIDriver(app=auth.router.mount())
    user1 = await _sign_in(d1)
    assert user1["ensName"] == "old.eth"

    # Mutate the resolver table (simulate ENS name change)
    table[addr.lower()] = "new.eth"

    d2 = ASGIDriver(app=auth.router.mount())
    user2 = await _sign_in(d2)
    # Same user row, refreshed
    assert user2["id"] == user1["id"]
    assert user2["ensName"] == "new.eth"
    row = await auth.context.adapter.find_one(
        model="user", where=(Where(field="id", value=user1["id"]),)
    )
    assert row["ensName"] == "new.eth"
