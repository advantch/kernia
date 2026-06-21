"""Ported from reference/packages/oauth-provider/src/pairwise.test.ts.

Covers pairwise subject identifiers (PPID) per OIDC core §8: per-sector
unlinkable `sub` in id_tokens, sector isolation by redirect-URI host, public
fallback, determinism, consistency across id_token/userinfo/introspection/
refresh, the user.id-in-JWT-access-token invariant, DCR validation, config
validation, and metadata advertisement.

Implementation notes for the Python port:
  * the sector identifier is the netloc (host:port) of the first redirect URI,
    so two clients on the same host share a sector (same pairwise sub) and two
    clients on different hosts get different subs;
  * the JWT access token carries the *real* user.id as `sub` (for user lookup),
    while the id_token / userinfo / introspection carry the pairwise sub;
  * `create_client` is the programmatic equivalent of `adminCreateOAuthClient`,
    and `/oauth2/register` is the DCR endpoint.
"""

from __future__ import annotations

import pytest
from kernia.auth import init
from kernia.error import APIError
from kernia.plugins.email_password import email_and_password
from kernia.plugins.jwt import jwt
from kernia.types.init_options import KerniaOptions
from kernia_memory_adapter import memory_adapter
from kernia_oauth_provider import OAuthProviderOptions, oauth_provider
from kernia_oauth_provider.plugin import create_client
from kernia_test_utils import ASGIDriver

from .conftest import (
    authorize_code,
    decode_jwt_payload,
    exchange_code,
    make_auth,
    signup,
)

PAIRWISE_SECRET = "test-pairwise-secret-key-32chars!!"

# Two distinct hosts → two sectors. Same host (different path) → one sector.
RP_A = "https://rp-a.test/api/auth/oauth2/callback/test-a"
RP_B = "https://rp-b.test/api/auth/oauth2/callback/test-b"
RP_A_SAME_HOST = "https://rp-a.test/api/auth/oauth2/callback/test-same"
RP_PUBLIC = "https://rp-a.test/api/auth/oauth2/callback/test-public"

SCOPES = ("openid", "profile", "email", "offline_access")


async def _get_tokens(driver, client):
    """Full authorize→token round-trip, returning the token response body."""
    code, verifier = await authorize_code(
        driver, client, scope="openid profile email offline_access"
    )
    r = await exchange_code(driver, client, code, verifier)
    assert r.status == 200, r.json()
    return r.json()


# ---------------------------------------------------------------------------
# pairwise subject identifiers
# ---------------------------------------------------------------------------


@pytest.fixture
async def pairwise_env():
    """Signed-in user plus pairwise clients A/B/same-host and a public client."""
    auth = make_auth(pairwise_secret=PAIRWISE_SECRET)
    driver = ASGIDriver(app=auth.router.mount())
    await signup(driver)
    client_a = await create_client(
        auth.context,
        name="A",
        redirect_uris=[RP_A],
        allowed_scopes=SCOPES,
        subject_type="pairwise",
    )
    client_b = await create_client(
        auth.context,
        name="B",
        redirect_uris=[RP_B],
        allowed_scopes=SCOPES,
        subject_type="pairwise",
    )
    client_same = await create_client(
        auth.context,
        name="SameHost",
        redirect_uris=[RP_A_SAME_HOST],
        allowed_scopes=SCOPES,
        subject_type="pairwise",
    )
    client_public = await create_client(
        auth.context,
        name="Public",
        redirect_uris=[RP_PUBLIC],
        allowed_scopes=SCOPES,
    )
    return auth, driver, client_a, client_b, client_same, client_public


async def test_different_sub_across_pairwise_clients(pairwise_env) -> None:
    _auth, driver, client_a, client_b, _same, _public = pairwise_env
    tokens_a = await _get_tokens(driver, client_a)
    tokens_b = await _get_tokens(driver, client_b)

    id_a = decode_jwt_payload(tokens_a["id_token"])
    id_b = decode_jwt_payload(tokens_b["id_token"])
    assert id_a["sub"]
    assert id_b["sub"]
    assert id_a["sub"] != id_b["sub"]


async def test_same_sub_for_same_pairwise_client_determinism(pairwise_env) -> None:
    _auth, driver, client_a, *_ = pairwise_env
    t1 = await _get_tokens(driver, client_a)
    t2 = await _get_tokens(driver, client_a)
    assert decode_jwt_payload(t1["id_token"])["sub"] == (decode_jwt_payload(t2["id_token"])["sub"])


async def test_public_client_returns_user_id_fallback(pairwise_env) -> None:
    _auth, driver, client_a, _b, _same, client_public = pairwise_env
    public_tokens = await _get_tokens(driver, client_public)
    pairwise_tokens = await _get_tokens(driver, client_a)

    public_sub = decode_jwt_payload(public_tokens["id_token"])["sub"]
    pairwise_sub = decode_jwt_payload(pairwise_tokens["id_token"])["sub"]
    assert public_sub
    assert public_sub != pairwise_sub


async def test_same_host_clients_share_pairwise_sub(pairwise_env) -> None:
    _auth, driver, client_a, _b, client_same, _public = pairwise_env
    tokens_a = await _get_tokens(driver, client_a)
    tokens_same = await _get_tokens(driver, client_same)

    assert (
        decode_jwt_payload(tokens_a["id_token"])["sub"]
        == (decode_jwt_payload(tokens_same["id_token"])["sub"])
    )


async def test_id_token_and_userinfo_sub_consistent(pairwise_env) -> None:
    _auth, driver, client_a, *_ = pairwise_env
    tokens = await _get_tokens(driver, client_a)
    id_sub = decode_jwt_payload(tokens["id_token"])["sub"]

    r = await driver.request(
        "GET",
        "/oauth2/userinfo",
        headers={"authorization": f"Bearer {tokens['access_token']}"},
    )
    assert r.status == 200, r.json()
    assert r.json()["sub"] == id_sub


async def test_introspection_returns_pairwise_sub(pairwise_env) -> None:
    _auth, driver, client_a, *_ = pairwise_env
    tokens = await _get_tokens(driver, client_a)

    r = await driver.request(
        "POST",
        "/oauth2/introspect",
        json_body={
            "client_id": client_a.client_id,
            "client_secret": client_a.client_secret,
            "token": tokens["access_token"],
            "token_type_hint": "access_token",
        },
    )
    assert r.status == 200, r.json()
    body = r.json()
    assert body["active"] is True
    assert body["sub"] == decode_jwt_payload(tokens["id_token"])["sub"]


async def test_pairwise_sub_preserved_after_refresh(pairwise_env) -> None:
    _auth, driver, client_a, *_ = pairwise_env
    tokens = await _get_tokens(driver, client_a)
    original_sub = decode_jwt_payload(tokens["id_token"])["sub"]

    r = await driver.request(
        "POST",
        "/oauth2/token",
        json_body={
            "grant_type": "refresh_token",
            "refresh_token": tokens["refresh_token"],
            "client_id": client_a.client_id,
            "client_secret": client_a.client_secret,
        },
    )
    assert r.status == 200, r.json()
    refreshed = r.json()
    assert refreshed["id_token"]
    assert decode_jwt_payload(refreshed["id_token"])["sub"] == original_sub


async def test_jwt_access_token_keeps_user_id_not_pairwise(pairwise_env) -> None:
    _auth, driver, client_a, *_ = pairwise_env
    tokens = await _get_tokens(driver, client_a)

    access = decode_jwt_payload(tokens["access_token"])
    id_token = decode_jwt_payload(tokens["id_token"])
    assert access["sub"]
    assert access["sub"] != id_token["sub"]


# ---------------------------------------------------------------------------
# pairwise DCR / admin-create validation
# ---------------------------------------------------------------------------


async def test_reject_pairwise_when_secret_not_configured() -> None:
    auth = make_auth()  # no pairwise_secret
    with pytest.raises(APIError):
        await create_client(
            auth.context,
            name="X",
            redirect_uris=[RP_A],
            subject_type="pairwise",
        )


async def test_accept_pairwise_when_secret_configured() -> None:
    auth = make_auth(pairwise_secret="test-secret-for-dcr-test-32chars!")
    client = await create_client(
        auth.context,
        name="X",
        redirect_uris=[RP_A],
        subject_type="pairwise",
    )
    assert client.client_id
    assert client.subject_type == "pairwise"


async def test_default_to_public_when_no_subject_type() -> None:
    auth = make_auth(pairwise_secret="test-secret-for-dcr-test-32chars!")
    client = await create_client(auth.context, name="X", redirect_uris=[RP_A])
    assert client.client_id
    assert client.subject_type is None


async def test_reject_pairwise_redirect_uris_on_different_hosts() -> None:
    auth = make_auth(pairwise_secret="test-secret-for-dcr-test-32chars!")
    with pytest.raises(APIError):
        await create_client(
            auth.context,
            name="X",
            redirect_uris=[
                "https://app-a.example.com/callback",
                "https://app-b.example.com/callback",
            ],
            subject_type="pairwise",
        )


async def test_accept_pairwise_redirect_uris_on_same_host() -> None:
    auth = make_auth(pairwise_secret="test-secret-for-dcr-test-32chars!")
    client = await create_client(
        auth.context,
        name="X",
        redirect_uris=[
            "https://app.example.com/callback-a",
            "https://app.example.com/callback-b",
        ],
        subject_type="pairwise",
    )
    assert client.client_id
    assert client.subject_type == "pairwise"


async def test_round_trip_subject_type_through_dcr() -> None:
    auth = make_auth(pairwise_secret="test-secret-for-dcr-test-32chars!")
    driver = ASGIDriver(app=auth.router.mount())
    await signup(driver)

    r = await driver.request(
        "POST",
        "/oauth2/register",
        json_body={
            "name": "DCR Client",
            "redirect_uris": [RP_A],
            "subject_type": "pairwise",
            "token_endpoint_auth_method": "none",
        },
    )
    assert r.status in (200, 201), r.json()
    assert r.json()["subject_type"] == "pairwise"


# ---------------------------------------------------------------------------
# pairwise configuration validation
# ---------------------------------------------------------------------------


def test_reject_pairwise_secret_shorter_than_32() -> None:
    with pytest.raises(Exception, match="at least 32 characters"):
        OAuthProviderOptions(issuer="https://issuer.test", pairwise_secret="too-short")


def test_accept_pairwise_secret_32_or_more() -> None:
    OAuthProviderOptions(
        issuer="https://issuer.test",
        pairwise_secret="a-valid-secret-that-is-32-chars!",
    )


# ---------------------------------------------------------------------------
# pairwise metadata
# ---------------------------------------------------------------------------


def _build_for_metadata(*, pairwise: bool):
    opts = {"issuer": "https://issuer.test", "enable_dynamic_registration": True}
    if pairwise:
        opts["pairwise_secret"] = "test-pairwise-metadata-secret!!!!"
    return init(
        KerniaOptions(
            database=memory_adapter(),
            secret="test-secret-32-characters-long!!!",
            plugins=[
                email_and_password(),
                jwt(),
                oauth_provider(OAuthProviderOptions(**opts)),
            ],
            advanced={"disable_csrf_check": True},
        )
    )


async def test_metadata_includes_pairwise_when_secret_configured() -> None:
    auth = _build_for_metadata(pairwise=True)
    driver = ASGIDriver(app=auth.router.mount())
    r = await driver.request("GET", "/.well-known/openid-configuration")
    assert r.status == 200, r.json()
    assert r.json()["subject_types_supported"] == ["public", "pairwise"]


async def test_metadata_only_public_without_secret() -> None:
    auth = _build_for_metadata(pairwise=False)
    driver = ASGIDriver(app=auth.router.mount())
    r = await driver.request("GET", "/.well-known/openid-configuration")
    assert r.status == 200, r.json()
    assert r.json()["subject_types_supported"] == ["public"]
