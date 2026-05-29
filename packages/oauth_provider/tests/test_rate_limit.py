"""Ported from the "oauth - rate limiting" describe block in
reference/packages/oauth-provider/src/oauth.test.ts.

Covers the plugin's advertised `rate_limit` rule set: the six default
per-endpoint rules, `{window, max}` overrides, `False` to disable a rule, and
live enforcement (200s up to the limit, then 429) on the token endpoint via the
core rate-limiter.

The Python port exposes rules as `RateLimitRule(path=, window=, max=)` rather
than upstream's `pathMatcher` closures, so rules are matched by `rule.path`.
"""

from __future__ import annotations

from better_auth.auth import init
from better_auth.plugins.email_password import email_and_password
from better_auth.plugins.jwt import jwt
from better_auth.types.init_options import BetterAuthOptions, RateLimitOptions
from better_auth_memory_adapter import memory_adapter
from better_auth_oauth_provider import OAuthProviderOptions, oauth_provider
from better_auth_oauth_provider.plugin import create_client
from better_auth_test_utils import ASGIDriver

from .conftest import ISSUER, signup


def _rule(plugin, path):
    return next((r for r in plugin.rate_limit if r.path == path), None)


# ---------------------------------------------------------------------------
# default / override / disable rule sets
# ---------------------------------------------------------------------------


def test_default_rate_limits_configured() -> None:
    plugin = oauth_provider(OAuthProviderOptions(issuer=ISSUER))
    assert len(plugin.rate_limit) == 6

    expected = {
        "/oauth2/token": (60, 20),
        "/oauth2/authorize": (60, 30),
        "/oauth2/introspect": (60, 100),
        "/oauth2/revoke": (60, 30),
        "/oauth2/register": (60, 5),
        "/oauth2/userinfo": (60, 60),
    }
    for path, (window, max_) in expected.items():
        rule = _rule(plugin, path)
        assert rule is not None, path
        assert (rule.window, rule.max) == (window, max_), path


def test_custom_rate_limit_values() -> None:
    plugin = oauth_provider(
        OAuthProviderOptions(
            issuer=ISSUER,
            rate_limit={
                "token": {"window": 1, "max": 4},
                "introspect": {"window": 1, "max": 50},
            },
        )
    )
    token_rule = _rule(plugin, "/oauth2/token")
    assert (token_rule.window, token_rule.max) == (1, 4)
    introspect_rule = _rule(plugin, "/oauth2/introspect")
    assert (introspect_rule.window, introspect_rule.max) == (1, 50)

    # Other endpoints keep defaults.
    authorize_rule = _rule(plugin, "/oauth2/authorize")
    assert (authorize_rule.window, authorize_rule.max) == (60, 30)


def test_disable_rate_limit_for_specific_endpoints() -> None:
    plugin = oauth_provider(
        OAuthProviderOptions(
            issuer=ISSUER,
            rate_limit={"token": False, "introspect": False},
        )
    )
    assert len(plugin.rate_limit) == 4
    assert _rule(plugin, "/oauth2/token") is None
    assert _rule(plugin, "/oauth2/introspect") is None
    assert _rule(plugin, "/oauth2/authorize") is not None


# ---------------------------------------------------------------------------
# live enforcement on the token endpoint
# ---------------------------------------------------------------------------


def _build_enforcing(rate_limit):
    auth = init(
        BetterAuthOptions(
            database=memory_adapter(),
            secret="test-secret-32-characters-long!!!",
            plugins=[
                email_and_password(),
                jwt(),
                oauth_provider(
                    OAuthProviderOptions(issuer=ISSUER, rate_limit=rate_limit)
                ),
            ],
            advanced={"disable_csrf_check": True},
            rate_limit=RateLimitOptions(enabled=True),
        )
    )
    return auth, ASGIDriver(app=auth.router.mount())


async def _client_credentials_request(driver, client):
    return await driver.request(
        "POST",
        "/oauth2/token",
        json_body={
            "grant_type": "client_credentials",
            "client_id": client.client_id,
            "client_secret": client.client_secret,
        },
    )


async def test_enforces_rate_limit_on_token_endpoint() -> None:
    auth, driver = _build_enforcing({"token": {"window": 60, "max": 3}})
    await signup(driver)
    client = await create_client(
        auth.context,
        name="CC Client",
        redirect_uris=["http://localhost:5000/callback"],
        allowed_scopes=("openid",),
    )

    statuses = [
        (await _client_credentials_request(driver, client)).status for _ in range(5)
    ]
    # First 3 within the window succeed; the last 2 are rate limited.
    assert statuses[0] == 200
    assert statuses[1] == 200
    assert statuses[2] == 200
    assert statuses[3] == 429
    assert statuses[4] == 429


async def test_does_not_rate_limit_when_endpoint_disabled() -> None:
    auth, driver = _build_enforcing({"token": False})
    await signup(driver)
    client = await create_client(
        auth.context,
        name="CC Client",
        redirect_uris=["http://localhost:5000/callback"],
        allowed_scopes=("openid",),
    )

    for _ in range(10):
        r = await _client_credentials_request(driver, client)
        assert r.status == 200, r.json()
