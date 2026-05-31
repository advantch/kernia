"""Unit tests for the generic-OAuth plugin.

Covers: config validation, discovery URL merging, authorize URL construction.
"""

from __future__ import annotations

import httpx
import pytest

from kernia.plugins.generic_oauth import (
    GenericOAuthConfig,
    auth0,
    generic_oauth,
    keycloak,
    okta,
)
from kernia.plugins.generic_oauth.routes import _DISCOVERY_CACHE, _resolve


def test_config_requires_endpoints_or_discovery() -> None:
    with pytest.raises(ValueError, match="authorization_url"):
        GenericOAuthConfig(provider_id="x", client_id="a", client_secret="b")


def test_config_accepts_discovery_only() -> None:
    cfg = GenericOAuthConfig(
        provider_id="x",
        client_id="a",
        client_secret="b",
        discovery_url="https://idp/.well-known/openid-configuration",
    )
    assert cfg.provider_id == "x"


def test_plugin_rejects_duplicate_provider_ids() -> None:
    cfg = GenericOAuthConfig(
        provider_id="x",
        client_id="a",
        client_secret="b",
        authorization_url="https://idp/auth",
        token_url="https://idp/token",
    )
    with pytest.raises(ValueError, match="duplicate"):
        generic_oauth([cfg, cfg])


def test_helpers_construct_discovery_url() -> None:
    a = auth0(client_id="x", client_secret="y", domain="tenant.auth0.com")
    assert a.discovery_url == "https://tenant.auth0.com/.well-known/openid-configuration"
    o = okta(client_id="x", client_secret="y", issuer="https://x.okta.com/oauth2/default/")
    assert o.discovery_url == (
        "https://x.okta.com/oauth2/default/.well-known/openid-configuration"
    )
    k = keycloak(
        client_id="x",
        client_secret="y",
        issuer="https://kc.example.com/realms/MyRealm",
    )
    assert k.discovery_url == (
        "https://kc.example.com/realms/MyRealm/.well-known/openid-configuration"
    )


async def test_discovery_resolves_endpoints(monkeypatch) -> None:
    _DISCOVERY_CACHE.clear()
    discovery_doc = {
        "authorization_endpoint": "https://idp/auth",
        "token_endpoint": "https://idp/token",
        "userinfo_endpoint": "https://idp/userinfo",
        "issuer": "https://idp",
    }

    def _handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=discovery_doc)

    transport = httpx.MockTransport(_handler)

    # Patch httpx.AsyncClient default transport
    original = httpx.AsyncClient.__init__

    def patched(self, *args, **kwargs):
        kwargs["transport"] = transport
        original(self, *args, **kwargs)

    monkeypatch.setattr(httpx.AsyncClient, "__init__", patched)
    cfg = GenericOAuthConfig(
        provider_id="x",
        client_id="cid",
        client_secret="csec",
        discovery_url="https://idp/.well-known/openid-configuration",
    )
    plan = await _resolve(cfg)
    assert plan.authorization_url == "https://idp/auth"
    assert plan.token_url == "https://idp/token"
    assert plan.user_info_url == "https://idp/userinfo"
    assert plan.issuer == "https://idp"


def test_endpoints_are_registered() -> None:
    cfg = GenericOAuthConfig(
        provider_id="x",
        client_id="a",
        client_secret="b",
        authorization_url="https://idp/auth",
        token_url="https://idp/token",
    )
    plugin = generic_oauth([cfg])
    paths = {(e.options.method, e.path) for e in plugin.endpoints}
    assert ("GET", "/oauth2/sign-in/:providerId") in paths
    assert ("POST", "/sign-in/oauth2") in paths
    assert ("GET", "/oauth2/callback/:providerId") in paths
    assert ("POST", "/oauth2/callback/:providerId") in paths
    assert ("POST", "/oauth2/link") in paths
