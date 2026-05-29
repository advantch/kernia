"""Unit + integration tests for the OIDC provider plugin.

Drives the plugin through its ASGI surface using `ASGIDriver`. Covers:
  * client registration (programmatic + /oauth2/register)
  * full authorization-code flow with PKCE
  * refresh_token rotation
  * userinfo bearer auth
  * introspection + revocation
  * discovery doc
"""

from __future__ import annotations

import base64

import pytest
from better_auth.auth import init
from better_auth.error import APIError
from better_auth.oauth2 import pkce_challenge, pkce_verifier
from better_auth.plugins.email_password import email_and_password
from better_auth.plugins.jwt import jwt
from better_auth.types.adapter import Where
from better_auth.types.init_options import BetterAuthOptions
from better_auth_memory_adapter import memory_adapter
from better_auth_oauth_provider import OAuthProviderOptions, oauth_provider
from better_auth_oauth_provider.plugin import create_client
from better_auth_test_utils import ASGIDriver


def _basic(client_id: str, client_secret: str) -> str:
    token = base64.b64encode(f"{client_id}:{client_secret}".encode()).decode("ascii")
    return f"Basic {token}"


@pytest.fixture
async def setup():
    auth = init(
        BetterAuthOptions(
            database=memory_adapter(),
            secret="test-secret",
            plugins=[
                email_and_password(),
                jwt(),
                oauth_provider(
                    OAuthProviderOptions(
                        issuer="https://issuer.test",
                        enable_dynamic_registration=True,
                    )
                ),
            ],
            advanced={"disable_csrf_check": True},
        )
    )
    driver = ASGIDriver(app=auth.router.mount())
    client = await create_client(
        auth.context,
        name="Test Client",
        redirect_uris=["https://client.test/cb"],
        allowed_scopes=("openid", "profile", "email", "offline_access"),
    )
    return auth, driver, client


async def _signup_signin(driver: ASGIDriver) -> None:
    await driver.request(
        "POST",
        "/sign-up/email",
        json_body={"email": "u@test", "password": "correcthorse", "name": "Test User"},
    )


async def test_discovery_doc(setup) -> None:
    _, driver, _ = setup
    r = await driver.request("GET", "/.well-known/openid-configuration")
    assert r.status == 200
    j = r.json()
    assert j["issuer"] == "https://issuer.test"
    assert j["token_endpoint"].endswith("/oauth2/token")
    assert "authorization_code" in j["grant_types_supported"]


async def test_full_authorization_code_flow(setup) -> None:
    _, driver, client = setup
    await _signup_signin(driver)

    # 1. Hit authorize with the session cookie set (PKCE: offline_access requires it)
    verifier = pkce_verifier()
    challenge = pkce_challenge(verifier)
    query = (
        f"response_type=code&client_id={client.client_id}"
        f"&redirect_uri=https://client.test/cb&scope=openid%20email%20profile%20offline_access"
        f"&state=xyz&code_challenge={challenge}&code_challenge_method=S256"
    )
    r = await driver.request("GET", "/oauth2/authorize", query=query)
    assert r.status == 200, r.json()
    code = r.json()["code"]
    assert code

    # 2. Exchange the code for tokens (no Basic auth — use body)
    r = await driver.request(
        "POST",
        "/oauth2/token",
        json_body={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": "https://client.test/cb",
            "client_id": client.client_id,
            "client_secret": client.client_secret,
            "code_verifier": verifier,
        },
    )
    assert r.status == 200, r.json()
    body = r.json()
    assert body["token_type"] == "Bearer"
    assert "access_token" in body
    assert "id_token" in body
    assert "refresh_token" in body  # offline_access requested

    access_token = body["access_token"]
    refresh = body["refresh_token"]

    # 3. /userinfo
    r = await driver.request(
        "GET",
        "/oauth2/userinfo",
        headers={"authorization": f"Bearer {access_token}"},
    )
    assert r.status == 200, r.json()
    info = r.json()
    assert info["email"] == "u@test"
    assert info["name"] == "Test User"

    # 4. /introspect on access token (RFC 7662: requires client auth)
    r = await driver.request(
        "POST",
        "/oauth2/introspect",
        json_body={
            "token": access_token,
            "client_id": client.client_id,
            "client_secret": client.client_secret,
        },
    )
    assert r.status == 200
    assert r.json()["active"] is True
    assert r.json()["sub"]

    # 5. /token refresh
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
    assert r.status == 200, r.json()
    new_access = r.json()["access_token"]
    new_refresh = r.json()["refresh_token"]
    assert new_access != access_token
    assert new_refresh != refresh

    # 6. Old refresh token is invalidated
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
    assert r.status == 400

    # 7. Revoke new refresh
    r = await driver.request(
        "POST",
        "/oauth2/revoke",
        json_body={"token": new_refresh, "client_id": client.client_id, "client_secret": client.client_secret},
    )
    assert r.status == 200


async def test_authorize_requires_session(setup) -> None:
    _, driver, client = setup
    # No sign-in
    r = await driver.request(
        "GET",
        "/oauth2/authorize",
        query=(
            f"response_type=code&client_id={client.client_id}"
            f"&redirect_uri=https://client.test/cb&scope=openid"
        ),
    )
    assert r.status == 401


async def test_authorize_rejects_bad_redirect(setup) -> None:
    _, driver, client = setup
    await _signup_signin(driver)
    r = await driver.request(
        "GET",
        "/oauth2/authorize",
        query=(
            f"response_type=code&client_id={client.client_id}"
            f"&redirect_uri=https://evil.test/cb&scope=openid"
        ),
    )
    assert r.status == 400


async def test_pkce_round_trip(setup) -> None:
    _, driver, client = setup
    await _signup_signin(driver)

    verifier = pkce_verifier()
    challenge = pkce_challenge(verifier)
    query = (
        f"response_type=code&client_id={client.client_id}"
        f"&redirect_uri=https://client.test/cb&scope=openid"
        f"&code_challenge={challenge}&code_challenge_method=S256"
    )
    r = await driver.request("GET", "/oauth2/authorize", query=query)
    assert r.status == 200
    code = r.json()["code"]

    # Wrong verifier → 401 (mirrors upstream "code verification failed")
    r = await driver.request(
        "POST",
        "/oauth2/token",
        json_body={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": "https://client.test/cb",
            "client_id": client.client_id,
            "client_secret": client.client_secret,
            "code_verifier": "wrong-verifier",
        },
    )
    assert r.status == 401


async def test_dynamic_registration(setup) -> None:
    _, driver, _ = setup
    r = await driver.request(
        "POST",
        "/oauth2/register",
        json_body={
            "name": "Dynamic App",
            "redirect_uris": ["https://dyn.test/cb"],
            "allowed_scopes": ["openid", "email"],
            "token_endpoint_auth_method": "client_secret_basic",
        },
    )
    assert r.status == 200, r.json()
    j = r.json()
    assert j["client_id"]
    assert j["client_secret"]


async def test_dynamic_registration_disabled() -> None:
    auth = init(
        BetterAuthOptions(
            database=memory_adapter(),
            secret="s",
            plugins=[
                email_and_password(),
                jwt(),
                oauth_provider(OAuthProviderOptions(issuer="https://issuer.test")),
            ],
            advanced={"disable_csrf_check": True},
        )
    )
    d = ASGIDriver(app=auth.router.mount())
    r = await d.request(
        "POST",
        "/oauth2/register",
        json_body={"name": "x", "redirect_uris": ["https://x/cb"]},
    )
    assert r.status == 404


async def test_oauth_authorization_server_metadata(setup) -> None:
    # RFC 8414: the OAuth 2.0 authorization-server metadata document.
    _, driver, _ = setup
    r = await driver.request("GET", "/.well-known/oauth-authorization-server")
    assert r.status == 200, r.json()
    j = r.json()
    assert j["issuer"] == "https://issuer.test"
    assert j["token_endpoint"].endswith("/oauth2/token")
    assert j["authorization_endpoint"].endswith("/oauth2/authorize")
    # RFC 8414 doc is the OAuth (non-OIDC) profile: no userinfo/id_token claims.
    assert "userinfo_endpoint" not in j


async def test_client_secret_stored_hashed(setup) -> None:
    # A DB leak must never expose a usable client secret: the stored value is a
    # SHA-256 digest, not the plaintext returned to the caller.
    auth, _, client = setup
    row = await auth.context.adapter.find_one(
        model="oauthClient",
        where=[Where(field="clientId", value=client.client_id)],
    )
    assert row is not None
    assert row["clientSecret"] != client.client_secret
    assert client.client_secret  # the caller still gets the usable plaintext


async def test_refresh_token_reuse_invalidates_family(setup) -> None:
    # RFC 9700 §4.14: replaying a rotated refresh token tears down the whole
    # family, so the *new* refresh token issued by the legitimate rotation is
    # also revoked.
    _, driver, client = setup
    await _signup_signin(driver)
    verifier = pkce_verifier()
    challenge = pkce_challenge(verifier)
    query = (
        f"response_type=code&client_id={client.client_id}"
        f"&redirect_uri=https://client.test/cb&scope=openid%20offline_access"
        f"&code_challenge={challenge}&code_challenge_method=S256"
    )
    r = await driver.request("GET", "/oauth2/authorize", query=query)
    code = r.json()["code"]
    r = await driver.request(
        "POST",
        "/oauth2/token",
        json_body={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": "https://client.test/cb",
            "client_id": client.client_id,
            "client_secret": client.client_secret,
            "code_verifier": verifier,
        },
    )
    original_refresh = r.json()["refresh_token"]

    # Legitimate rotation
    r = await driver.request(
        "POST",
        "/oauth2/token",
        json_body={
            "grant_type": "refresh_token",
            "refresh_token": original_refresh,
            "client_id": client.client_id,
            "client_secret": client.client_secret,
        },
    )
    assert r.status == 200
    rotated_refresh = r.json()["refresh_token"]

    # Replay the consumed (original) token → detected reuse, family torn down
    r = await driver.request(
        "POST",
        "/oauth2/token",
        json_body={
            "grant_type": "refresh_token",
            "refresh_token": original_refresh,
            "client_id": client.client_id,
            "client_secret": client.client_secret,
        },
    )
    assert r.status == 400

    # The legitimately-rotated token is now also dead (family invalidation)
    r = await driver.request(
        "POST",
        "/oauth2/token",
        json_body={
            "grant_type": "refresh_token",
            "refresh_token": rotated_refresh,
            "client_id": client.client_id,
            "client_secret": client.client_secret,
        },
    )
    assert r.status == 400


async def test_client_credentials_grant(setup) -> None:
    _, driver, client = setup
    r = await driver.request(
        "POST",
        "/oauth2/token",
        json_body={
            "grant_type": "client_credentials",
            "scope": "read",
        },
        headers={"authorization": _basic(client.client_id, client.client_secret)},
    )
    assert r.status == 200, r.json()
    body = r.json()
    assert "access_token" in body
    assert "id_token" not in body  # no id_token for client_credentials


async def test_client_credentials_rejects_oidc_scope(setup) -> None:
    # client_credentials has no end user, so identity scopes are rejected.
    _, driver, client = setup
    r = await driver.request(
        "POST",
        "/oauth2/token",
        json_body={"grant_type": "client_credentials", "scope": "openid"},
        headers={"authorization": _basic(client.client_id, client.client_secret)},
    )
    assert r.status == 400
    assert r.json()["data"]["error"] == "invalid_scope"


async def test_introspect_requires_client_auth(setup) -> None:
    # RFC 7662 §2.1: unauthenticated introspection requests are rejected.
    _, driver, _ = setup
    r = await driver.request(
        "POST",
        "/oauth2/introspect",
        json_body={"token": "anything"},
    )
    assert r.status == 401
    assert r.json()["data"]["error"] == "invalid_client"


async def test_revoke_requires_client_auth(setup) -> None:
    # RFC 7009 §2.1: unauthenticated revocation requests are rejected.
    _, driver, _ = setup
    r = await driver.request(
        "POST",
        "/oauth2/revoke",
        json_body={"token": "anything"},
    )
    assert r.status == 401
    assert r.json()["data"]["error"] == "invalid_client"


# ----- pairwise subject identifiers -----


def _decode_jwt_payload(token: str) -> dict:
    import json

    payload_b64 = token.split(".")[1]
    payload_b64 += "=" * (-len(payload_b64) % 4)
    return json.loads(base64.urlsafe_b64decode(payload_b64))


PAIRWISE_SECRET = "test-pairwise-secret-key-32chars!!"


@pytest.fixture
async def pairwise_setup():
    auth = init(
        BetterAuthOptions(
            database=memory_adapter(),
            secret="test-secret",
            plugins=[
                email_and_password(),
                jwt(),
                oauth_provider(
                    OAuthProviderOptions(
                        issuer="https://issuer.test",
                        enable_dynamic_registration=True,
                        pairwise_secret=PAIRWISE_SECRET,
                    )
                ),
            ],
            advanced={"disable_csrf_check": True},
        )
    )
    driver = ASGIDriver(app=auth.router.mount())
    await _signup_signin(driver)

    scopes = ("openid", "profile", "email", "offline_access")
    # Two pairwise clients on *different* hosts → different sectors.
    pairwise_a = await create_client(
        auth.context,
        name="Pairwise A",
        redirect_uris=["http://localhost:5000/cb-a"],
        allowed_scopes=scopes,
        subject_type="pairwise",
    )
    pairwise_b = await create_client(
        auth.context,
        name="Pairwise B",
        redirect_uris=["http://localhost:6000/cb-b"],
        allowed_scopes=scopes,
        subject_type="pairwise",
    )
    public = await create_client(
        auth.context,
        name="Public",
        redirect_uris=["http://localhost:5000/cb-public"],
        allowed_scopes=scopes,
    )
    # Same host as pairwise_a → same sector → same sub.
    same_host = await create_client(
        auth.context,
        name="Same Host",
        redirect_uris=["http://localhost:5000/cb-same"],
        allowed_scopes=scopes,
        subject_type="pairwise",
    )
    return auth, driver, pairwise_a, pairwise_b, public, same_host


async def _get_tokens(driver: ASGIDriver, client) -> dict:
    redirect_uri = client.redirect_uris[0]
    verifier = pkce_verifier()
    challenge = pkce_challenge(verifier)
    query = (
        f"response_type=code&client_id={client.client_id}"
        f"&redirect_uri={redirect_uri}"
        f"&scope=openid%20profile%20email%20offline_access"
        f"&code_challenge={challenge}&code_challenge_method=S256"
    )
    r = await driver.request("GET", "/oauth2/authorize", query=query)
    assert r.status == 200, r.json()
    code = r.json()["code"]
    body = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": redirect_uri,
        "client_id": client.client_id,
        "client_secret": client.client_secret,
        "code_verifier": verifier,
    }
    if client.client_secret is None:
        body.pop("client_secret")
    r = await driver.request("POST", "/oauth2/token", json_body=body)
    assert r.status == 200, r.json()
    return r.json()


async def test_pairwise_different_sub_across_clients(pairwise_setup) -> None:
    # cross-RP unlinkability: different sectors → different pairwise sub
    _, driver, a, b, _, _ = pairwise_setup
    tokens_a = await _get_tokens(driver, a)
    tokens_b = await _get_tokens(driver, b)
    sub_a = _decode_jwt_payload(tokens_a["id_token"])["sub"]
    sub_b = _decode_jwt_payload(tokens_b["id_token"])["sub"]
    assert sub_a
    assert sub_b
    assert sub_a != sub_b


async def test_pairwise_same_sub_for_same_client(pairwise_setup) -> None:
    # determinism: same pairwise client → same sub
    _, driver, a, _, _, _ = pairwise_setup
    t1 = await _get_tokens(driver, a)
    t2 = await _get_tokens(driver, a)
    s1 = _decode_jwt_payload(t1["id_token"])["sub"]
    s2 = _decode_jwt_payload(t2["id_token"])["sub"]
    assert s1 == s2


async def test_pairwise_public_client_uses_user_id(pairwise_setup) -> None:
    # public client sub differs from pairwise sub for the same user
    _, driver, a, _, public, _ = pairwise_setup
    public_tokens = await _get_tokens(driver, public)
    pairwise_tokens = await _get_tokens(driver, a)
    public_sub = _decode_jwt_payload(public_tokens["id_token"])["sub"]
    pairwise_sub = _decode_jwt_payload(pairwise_tokens["id_token"])["sub"]
    assert public_sub
    assert public_sub != pairwise_sub


async def test_pairwise_same_host_same_sub(pairwise_setup) -> None:
    # same host → same sector → same pairwise sub
    _, driver, a, _, _, same_host = pairwise_setup
    tokens_a = await _get_tokens(driver, a)
    tokens_same = await _get_tokens(driver, same_host)
    sub_a = _decode_jwt_payload(tokens_a["id_token"])["sub"]
    sub_same = _decode_jwt_payload(tokens_same["id_token"])["sub"]
    assert sub_a == sub_same


async def test_pairwise_consistent_sub_idtoken_userinfo(pairwise_setup) -> None:
    _, driver, a, _, _, _ = pairwise_setup
    tokens = await _get_tokens(driver, a)
    id_sub = _decode_jwt_payload(tokens["id_token"])["sub"]
    r = await driver.request(
        "GET",
        "/oauth2/userinfo",
        headers={"authorization": f"Bearer {tokens['access_token']}"},
    )
    assert r.status == 200, r.json()
    assert r.json()["sub"] == id_sub


async def test_pairwise_sub_in_introspection(pairwise_setup) -> None:
    _, driver, a, _, _, _ = pairwise_setup
    tokens = await _get_tokens(driver, a)
    id_sub = _decode_jwt_payload(tokens["id_token"])["sub"]
    r = await driver.request(
        "POST",
        "/oauth2/introspect",
        json_body={
            "client_id": a.client_id,
            "client_secret": a.client_secret,
            "token": tokens["access_token"],
            "token_type_hint": "access_token",
        },
    )
    assert r.status == 200, r.json()
    assert r.json()["active"] is True
    assert r.json()["sub"] == id_sub


async def test_pairwise_sub_preserved_after_refresh(pairwise_setup) -> None:
    _, driver, a, _, _, _ = pairwise_setup
    tokens = await _get_tokens(driver, a)
    original_sub = _decode_jwt_payload(tokens["id_token"])["sub"]
    r = await driver.request(
        "POST",
        "/oauth2/token",
        json_body={
            "grant_type": "refresh_token",
            "client_id": a.client_id,
            "client_secret": a.client_secret,
            "refresh_token": tokens["refresh_token"],
        },
    )
    assert r.status == 200, r.json()
    refreshed_sub = _decode_jwt_payload(r.json()["id_token"])["sub"]
    assert refreshed_sub == original_sub


async def test_pairwise_access_token_keeps_user_id(pairwise_setup) -> None:
    # JWT access token carries the real user.id for lookup, not the pairwise sub.
    _, driver, a, _, _, _ = pairwise_setup
    tokens = await _get_tokens(driver, a)
    access_sub = _decode_jwt_payload(tokens["access_token"])["sub"]
    id_sub = _decode_jwt_payload(tokens["id_token"])["sub"]
    assert access_sub
    assert access_sub != id_sub


# ----- pairwise DCR validation -----


def _pairwise_auth(*, secret: str | None):
    plugins = [email_and_password(), jwt()]
    opts_kwargs: dict = {"issuer": "https://issuer.test", "enable_dynamic_registration": True}
    if secret is not None:
        opts_kwargs["pairwise_secret"] = secret
    plugins.append(oauth_provider(OAuthProviderOptions(**opts_kwargs)))
    return init(
        BetterAuthOptions(
            database=memory_adapter(),
            secret="s",
            plugins=plugins,
            advanced={"disable_csrf_check": True},
        )
    )


async def test_dcr_rejects_pairwise_without_secret() -> None:
    auth = _pairwise_auth(secret=None)
    with pytest.raises(APIError):
        await create_client(
            auth.context,
            name="x",
            redirect_uris=["https://app.example.com/cb"],
            subject_type="pairwise",
        )


async def test_dcr_accepts_pairwise_with_secret() -> None:
    auth = _pairwise_auth(secret=PAIRWISE_SECRET)
    client = await create_client(
        auth.context,
        name="x",
        redirect_uris=["https://app.example.com/cb"],
        subject_type="pairwise",
    )
    assert client.client_id
    assert client.subject_type == "pairwise"


async def test_dcr_defaults_to_public() -> None:
    auth = _pairwise_auth(secret=PAIRWISE_SECRET)
    client = await create_client(
        auth.context,
        name="x",
        redirect_uris=["https://app.example.com/cb"],
    )
    assert client.client_id
    assert client.subject_type is None


async def test_dcr_rejects_pairwise_multi_host() -> None:
    auth = _pairwise_auth(secret=PAIRWISE_SECRET)
    with pytest.raises(APIError):
        await create_client(
            auth.context,
            name="x",
            redirect_uris=[
                "https://app-a.example.com/cb",
                "https://app-b.example.com/cb",
            ],
            subject_type="pairwise",
        )


async def test_dcr_accepts_pairwise_same_host() -> None:
    auth = _pairwise_auth(secret=PAIRWISE_SECRET)
    client = await create_client(
        auth.context,
        name="x",
        redirect_uris=[
            "https://app.example.com/cb-a",
            "https://app.example.com/cb-b",
        ],
        subject_type="pairwise",
    )
    assert client.client_id
    assert client.subject_type == "pairwise"


async def test_dcr_roundtrips_subject_type() -> None:
    auth = _pairwise_auth(secret=PAIRWISE_SECRET)
    d = ASGIDriver(app=auth.router.mount())
    r = await d.request(
        "POST",
        "/oauth2/register",
        json_body={
            "name": "dcr",
            "redirect_uris": ["https://app.example.com/cb"],
            "subject_type": "pairwise",
            "token_endpoint_auth_method": "none",
        },
    )
    assert r.status == 200, r.json()
    assert r.json()["subject_type"] == "pairwise"


# ----- pairwise configuration validation -----


def test_pairwise_secret_too_short_rejected() -> None:
    with pytest.raises(ValueError, match="pairwiseSecret must be at least 32"):
        OAuthProviderOptions(issuer="https://issuer.test", pairwise_secret="too-short")


def test_pairwise_secret_32_chars_accepted() -> None:
    OAuthProviderOptions(
        issuer="https://issuer.test",
        pairwise_secret="a-valid-secret-that-is-32-chars!",
    )


# ----- pairwise metadata -----


async def test_metadata_includes_pairwise_subject_type(pairwise_setup) -> None:
    _, driver, *_ = pairwise_setup
    r = await driver.request("GET", "/.well-known/openid-configuration")
    assert r.status == 200, r.json()
    assert r.json()["subject_types_supported"] == ["public", "pairwise"]


async def test_metadata_public_only_without_secret(setup) -> None:
    _, driver, _ = setup
    r = await driver.request("GET", "/.well-known/openid-configuration")
    assert r.status == 200, r.json()
    assert r.json()["subject_types_supported"] == ["public"]


async def test_metadata_oidc_field_set(setup) -> None:
    # Mirror upstream oidcServerMetadata field-for-field.
    _, driver, _ = setup
    r = await driver.request("GET", "/.well-known/openid-configuration")
    j = r.json()
    assert j["code_challenge_methods_supported"] == ["S256"]
    assert j["response_modes_supported"] == ["query"]
    assert j["authorization_response_iss_parameter_supported"] is True
    assert j["id_token_signing_alg_values_supported"] == ["EdDSA"]
    assert j["end_session_endpoint"].endswith("/oauth2/end-session")
    assert j["acr_values_supported"] == ["urn:mace:incommon:iap:bronze"]
    assert "login" in j["prompt_values_supported"]
    assert "sub" in j["claims_supported"]
    assert j["introspection_endpoint_auth_methods_supported"] == [
        "client_secret_basic",
        "client_secret_post",
    ]
