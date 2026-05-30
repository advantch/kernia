"""Ported from reference/packages/oauth-provider/src/token.test.ts.

The Python port issues self-contained JWT access tokens (no opaque/JWT split,
no token prefixes, no resource/audience binding, no custom-claim callbacks, no
encrypted-secret storage, no auth_time), so the prefix/resource/custom-claim/
auth_time/encrypted-secret cases are not portable. The grant-type behavior
(scope variants, code single-use, refresh rotation + scope narrowing, replay /
reuse detection) is ported.
"""

from __future__ import annotations

import pytest
from better_auth.types.adapter import Where

from .conftest import (
    authorize_code,
    basic,
    decode_jwt_payload,
    exchange_code,
    get_tokens,
)


async def _refresh(driver, client, refresh_token, scope=None):
    body = {
        "grant_type": "refresh_token",
        "refresh_token": refresh_token,
        "client_id": client.client_id,
        "client_secret": client.client_secret,
    }
    if scope is not None:
        body["scope"] = scope
    return await driver.request("POST", "/oauth2/token", json_body=body)


# ----- grant: authorization_code, scope variants -----


async def test_scope_openid_access_and_id_token(confidential) -> None:
    _, driver, client = confidential
    tokens = await get_tokens(driver, client, scope="openid")
    assert tokens["access_token"]
    assert tokens["id_token"]
    assert tokens["token_type"] == "Bearer"


async def test_scope_openid_profile(confidential) -> None:
    _, driver, client = confidential
    tokens = await get_tokens(driver, client, scope="openid profile")
    id_claims = decode_jwt_payload(tokens["id_token"])
    assert id_claims["name"] == "Test User"


async def test_scope_openid_email(confidential) -> None:
    _, driver, client = confidential
    tokens = await get_tokens(driver, client, scope="openid email")
    id_claims = decode_jwt_payload(tokens["id_token"])
    assert id_claims["email"] == "u@test"


async def test_scope_offline_access_yields_refresh(confidential) -> None:
    _, driver, client = confidential
    tokens = await get_tokens(driver, client, scope="openid offline_access")
    assert tokens["access_token"]
    assert tokens["id_token"]
    assert tokens["refresh_token"]


async def test_rejects_concurrent_redemption_of_same_code(confidential) -> None:
    _, driver, client = confidential
    code, verifier = await authorize_code(driver, client, scope="openid")
    r1 = await exchange_code(driver, client, code, verifier, scope="openid")
    assert r1.status == 200, r1.json()
    # Second redemption of the now-consumed code fails.
    r2 = await exchange_code(driver, client, code, verifier, scope="openid")
    assert r2.status == 400


# ----- grant: refresh_token -----


async def test_refresh_same_scopes(confidential) -> None:
    _, driver, client = confidential
    tokens = await get_tokens(driver, client, scope="openid offline_access")
    r = await _refresh(driver, client, tokens["refresh_token"])
    assert r.status == 200, r.json()
    body = r.json()
    assert body["access_token"] != tokens["access_token"]
    assert body["refresh_token"] != tokens["refresh_token"]


async def test_refresh_lesser_scopes(confidential) -> None:
    _, driver, client = confidential
    tokens = await get_tokens(driver, client, scope="openid email offline_access")
    r = await _refresh(driver, client, tokens["refresh_token"], scope="openid offline_access")
    assert r.status == 200, r.json()
    assert r.json()["scope"] == "openid offline_access"


async def test_refresh_cannot_widen_scopes(confidential) -> None:
    _, driver, client = confidential
    tokens = await get_tokens(driver, client, scope="openid offline_access")
    r = await _refresh(
        driver, client, tokens["refresh_token"], scope="openid email offline_access"
    )
    assert r.status == 400


async def test_replay_consumed_refresh_token_fails(confidential) -> None:
    _, driver, client = confidential
    tokens = await get_tokens(driver, client, scope="openid offline_access")
    first = await _refresh(driver, client, tokens["refresh_token"])
    assert first.status == 200
    # Replaying the now-rotated token is rejected.
    replay = await _refresh(driver, client, tokens["refresh_token"])
    assert replay.status == 400


async def test_reuse_tears_down_family(confidential) -> None:
    _, driver, client = confidential
    tokens = await get_tokens(driver, client, scope="openid offline_access")
    rotated = (await _refresh(driver, client, tokens["refresh_token"])).json()["refresh_token"]
    # Replay the consumed original -> family teardown.
    assert (await _refresh(driver, client, tokens["refresh_token"])).status == 400
    # The legitimately-rotated token is now dead too.
    assert (await _refresh(driver, client, rotated)).status == 400


# ----- grant: refresh_token, client authentication -----
#
# Ported from reference/.../mcp/mcp.test.ts
# describe("mcp refresh_token grant client authentication"). Upstream drives the
# mcp plugin's `/mcp/token` endpoint; in this port the OAuth *issuer* token
# exchange lives in the oauth-provider package at `/oauth2/token`, so the
# client-authentication behaviour is exercised there. A real refresh token is
# minted through the offline_access flow rather than seeded directly.


async def _seed_refresh_token(driver, client) -> str:
    tokens = await get_tokens(driver, client, scope="openid offline_access")
    return tokens["refresh_token"]


async def test_reject_refresh_token_on_confidential_client_without_client_secret(
    confidential,
) -> None:
    _, driver, client = confidential
    refresh = await _seed_refresh_token(driver, client)
    r = await driver.request(
        "POST",
        "/oauth2/token",
        json_body={
            "grant_type": "refresh_token",
            "refresh_token": refresh,
            "client_id": client.client_id,
        },
    )
    assert r.status == 401, r.json()
    assert r.json()["data"]["error"] == "invalid_client"
    assert "access_token" not in r.json()


async def test_reject_refresh_token_on_confidential_client_with_wrong_client_secret(
    confidential,
) -> None:
    _, driver, client = confidential
    refresh = await _seed_refresh_token(driver, client)
    r = await driver.request(
        "POST",
        "/oauth2/token",
        json_body={
            "grant_type": "refresh_token",
            "refresh_token": refresh,
            "client_id": client.client_id,
            "client_secret": "wrong-secret",
        },
    )
    assert r.status == 401, r.json()
    assert r.json()["data"]["error"] == "invalid_client"
    assert "access_token" not in r.json()


async def test_accept_refresh_token_when_client_secret_via_authorization_basic(
    confidential,
) -> None:
    _, driver, client = confidential
    refresh = await _seed_refresh_token(driver, client)
    r = await driver.request(
        "POST",
        "/oauth2/token",
        json_body={"grant_type": "refresh_token", "refresh_token": refresh},
        headers={"authorization": basic(client.client_id, client.client_secret)},
    )
    assert r.status == 200, r.json()
    body = r.json()
    assert body["access_token"]
    assert body["refresh_token"]


async def test_accept_refresh_token_when_basic_and_matching_client_id_in_body(
    confidential,
) -> None:
    _, driver, client = confidential
    refresh = await _seed_refresh_token(driver, client)
    r = await driver.request(
        "POST",
        "/oauth2/token",
        json_body={
            "grant_type": "refresh_token",
            "refresh_token": refresh,
            "client_id": client.client_id,
        },
        headers={"authorization": basic(client.client_id, client.client_secret)},
    )
    assert r.status == 200, r.json()
    assert r.json()["access_token"]


async def test_reject_refresh_token_when_body_client_id_mismatches_basic(
    confidential,
) -> None:
    _, driver, client = confidential
    refresh = await _seed_refresh_token(driver, client)
    r = await driver.request(
        "POST",
        "/oauth2/token",
        json_body={
            "grant_type": "refresh_token",
            "refresh_token": refresh,
            "client_id": "different-client-id",
        },
        headers={"authorization": basic(client.client_id, client.client_secret)},
    )
    assert r.status == 401, r.json()
    assert r.json()["data"]["error"] == "invalid_client"


async def test_reject_refresh_token_when_confidential_client_is_disabled(
    confidential,
) -> None:
    auth, driver, client = confidential
    refresh = await _seed_refresh_token(driver, client)
    await auth.context.adapter.update(
        model="oauthClient",
        where=(Where(field="clientId", value=client.client_id),),
        update={"disabled": True},
    )
    r = await driver.request(
        "POST",
        "/oauth2/token",
        json_body={
            "grant_type": "refresh_token",
            "refresh_token": refresh,
            "client_id": client.client_id,
            "client_secret": client.client_secret,
        },
    )
    assert r.status == 401, r.json()
    assert r.json()["data"]["error"] == "invalid_client"
    assert "access_token" not in r.json()


@pytest.mark.skip(
    reason="JS-only token features: opaque/JWT split, token/secret prefixes, "
    "resource/audience binding, custom id_token/userinfo claim callbacks, "
    "auth_time, and encrypted client-secret storage are not implemented in the "
    "Python port (stateless-JWT model)."
)
async def test_prefix_resource_custom_claim_and_encrypted_secret_cases() -> None:
    ...
