"""Ported from reference/packages/oauth-provider/src/metadata.test.ts.

The Python port advertises a fixed issuer (no dynamic baseURL-from-request) and
has no remoteJwks / disableJwtPlugin / protected-resource-metadata client, so
those cases are not portable (see skips). The discovery / auth-server metadata
field set, the openid-vs-oauth split, and advertised-metadata validation are
ported.
"""

from __future__ import annotations

import pytest
from kernia_oauth_provider import OAuthProviderOptions, oauth_provider
from kernia_test_utils import ASGIDriver

from .conftest import ISSUER, make_auth

BASE_CLAIMS = [
    "sub", "iss", "aud", "exp", "iat", "sid", "scope", "azp",
    "email", "email_verified", "name", "picture", "family_name", "given_name",
]


@pytest.fixture
async def driver():
    return ASGIDriver(app=make_auth().router.mount())


async def test_openid_config_full_field_set(driver) -> None:
    r = await driver.request("GET", "/.well-known/openid-configuration")
    assert r.status == 200, r.json()
    j = r.json()
    assert j["scopes_supported"] == ["openid", "profile", "email", "offline_access"]
    assert j["issuer"] == ISSUER
    assert j["authorization_endpoint"] == f"{ISSUER}/oauth2/authorize"
    assert j["token_endpoint"] == f"{ISSUER}/oauth2/token"
    assert j["jwks_uri"] == f"{ISSUER}/jwks"
    assert j["registration_endpoint"] == f"{ISSUER}/oauth2/register"
    assert j["introspection_endpoint"] == f"{ISSUER}/oauth2/introspect"
    assert j["revocation_endpoint"] == f"{ISSUER}/oauth2/revoke"
    assert j["response_types_supported"] == ["code"]
    assert j["response_modes_supported"] == ["query"]
    assert j["grant_types_supported"] == [
        "authorization_code", "client_credentials", "refresh_token",
    ]
    assert j["token_endpoint_auth_methods_supported"] == [
        "client_secret_basic", "client_secret_post",
    ]
    assert j["introspection_endpoint_auth_methods_supported"] == [
        "client_secret_basic", "client_secret_post",
    ]
    assert j["revocation_endpoint_auth_methods_supported"] == [
        "client_secret_basic", "client_secret_post",
    ]
    assert j["code_challenge_methods_supported"] == ["S256"]
    assert j["authorization_response_iss_parameter_supported"] is True
    assert j["claims_supported"] == BASE_CLAIMS
    assert j["userinfo_endpoint"] == f"{ISSUER}/oauth2/userinfo"
    assert j["subject_types_supported"] == ["public"]
    assert j["id_token_signing_alg_values_supported"] == ["EdDSA"]
    assert j["end_session_endpoint"] == f"{ISSUER}/oauth2/end-session"
    assert j["acr_values_supported"] == ["urn:mace:incommon:iap:bronze"]
    assert j["prompt_values_supported"] == [
        "login", "consent", "create", "select_account", "none",
    ]


async def test_oauth_server_config_matches_openid_subset(driver) -> None:
    oidc = (await driver.request("GET", "/.well-known/openid-configuration")).json()
    oauth = (
        await driver.request("GET", "/.well-known/oauth-authorization-server")
    ).json()
    for key in [
        "issuer", "authorization_endpoint", "token_endpoint", "jwks_uri",
        "grant_types_supported", "code_challenge_methods_supported",
    ]:
        assert oauth[key] == oidc[key]


async def test_no_openid_config_when_scope_absent() -> None:
    # An issuer that does not advertise "openid" is a pure OAuth 2.0 server.
    scopes = ("create:test",)
    auth = make_auth(supported_scopes=scopes)
    d = ASGIDriver(app=auth.router.mount())
    r = await d.request("GET", "/.well-known/openid-configuration")
    assert r.status == 404
    oauth = (await d.request("GET", "/.well-known/oauth-authorization-server")).json()
    assert oauth["scopes_supported"] == list(scopes)
    assert oauth["issuer"] == ISSUER


async def test_utilizes_advertised_metadata_fields() -> None:
    auth = make_auth(
        advertised_scopes_supported=("email",),
        advertised_claims_supported=("sub", "iss", "aud", "exp", "iat", "scope"),
    )
    d = ASGIDriver(app=auth.router.mount())
    j = (await d.request("GET", "/.well-known/openid-configuration")).json()
    assert j["scopes_supported"] == ["email"]
    assert j["claims_supported"] == ["sub", "iss", "aud", "exp", "iat", "scope"]


async def test_fails_if_advertised_scope_invalid() -> None:
    with pytest.raises(
        ValueError,
        match="advertisedMetadata.scopes_supported create:test not found in scopes",
    ):
        oauth_provider(
            OAuthProviderOptions(
                issuer=ISSUER, advertised_scopes_supported=("create:test",)
            )
        )


async def test_advertise_custom_claims() -> None:
    custom = ("http://example.com/roles",)
    auth = make_auth(advertised_claims_supported=tuple(BASE_CLAIMS) + custom)
    d = ASGIDriver(app=auth.router.mount())
    j = (await d.request("GET", "/.well-known/openid-configuration")).json()
    assert j["claims_supported"] == BASE_CLAIMS + list(custom)


@pytest.mark.skip(
    reason="Python port advertises a fixed configured issuer; no "
    "baseURL-from-request resolution, remoteJwks, or disableJwtPlugin alg "
    "switching (those are JS-only metadata-wrapper behaviors)."
)
async def test_dynamic_baseurl_and_jwks_alg_cases() -> None:
    ...


@pytest.mark.skip(
    reason="Protected-resource metadata (RFC 9728) is served by the separate "
    "mcp package in this port; the oauth-provider resource-metadata client is "
    "not implemented here."
)
async def test_protected_resource_metadata_cases() -> None:
    ...
