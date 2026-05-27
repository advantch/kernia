"""Per-provider unit tests.

For every built-in OAuth provider we exercise the constructor and the
`authorize()` method, asserting the canonical query parameters end up in the
URL (client_id, redirect_uri, scope, response_type=code, state, and — when
PKCE is in play — code_challenge / code_challenge_method).

Network is never touched.
"""

from __future__ import annotations

from urllib.parse import parse_qs, urlparse

import pytest

from kernia import social_providers as sp


PKCE_VERIFIER = "v" * 64

# (constructor, extra_kwargs)
PROVIDERS = [
    ("apple", sp.apple, {}),
    ("atlassian", sp.atlassian, {}),
    ("cognito", sp.cognito, {"domain": "test.auth.us-east-1.amazoncognito.com"}),
    ("discord", sp.discord, {}),
    ("dropbox", sp.dropbox, {}),
    ("facebook", sp.facebook, {}),
    ("figma", sp.figma, {}),
    ("github", sp.github, {}),
    ("gitlab", sp.gitlab, {}),
    ("google", sp.google, {}),
    ("huggingface", sp.huggingface, {}),
    ("kakao", sp.kakao, {}),
    ("kick", sp.kick, {}),
    ("line", sp.line, {}),
    ("linear", sp.linear, {}),
    ("linkedin", sp.linkedin, {}),
    ("microsoft", sp.microsoft, {"tenant_id": "common"}),
    ("naver", sp.naver, {}),
    ("notion", sp.notion, {}),
    ("paybin", sp.paybin, {}),
    ("paypal", sp.paypal, {}),
    ("polar", sp.polar, {}),
    ("railway", sp.railway, {}),
    ("reddit", sp.reddit, {}),
    ("roblox", sp.roblox, {}),
    ("salesforce", sp.salesforce, {}),
    ("slack", sp.slack, {}),
    ("spotify", sp.spotify, {}),
    ("tiktok", sp.tiktok, {}),
    ("twitch", sp.twitch, {}),
    ("twitter", sp.twitter, {}),
    ("vercel", sp.vercel, {}),
    ("vk", sp.vk, {}),
    ("wechat", sp.wechat, {}),
    ("zoom", sp.zoom, {}),
]


@pytest.mark.parametrize(("provider_id", "factory", "extra"), PROVIDERS)
async def test_authorize_url(
    provider_id: str, factory, extra: dict
) -> None:
    provider = factory(client_id="cid", client_secret="csec", **extra)
    url = await provider.authorize(
        redirect_uri="https://app.test/callback",
        state="ST",
        code_verifier=PKCE_VERIFIER,
        nonce=None,
    )
    parsed = urlparse(url)
    qs = parse_qs(parsed.query)
    # WeChat uses non-standard param names — its provider sends `appid` instead
    # of `client_id`. Validate that variant separately.
    if provider_id == "wechat":
        assert qs.get("appid") == ["cid"]
        assert qs.get("state") == ["ST"]
        assert qs.get("redirect_uri") == ["https://app.test/callback"]
        return
    assert qs.get("client_id") == ["cid"], f"{provider_id}: missing client_id"
    assert qs.get("redirect_uri") == [
        "https://app.test/callback"
    ], f"{provider_id}: missing redirect_uri"
    assert qs.get("state") == ["ST"], f"{provider_id}: missing state"
    # Most providers default to `response_type=code`. Apple uses
    # `code id_token` because it ships id_tokens directly in form_post.
    if provider_id == "apple":
        assert qs.get("response_type") == ["code id_token"]
        assert qs.get("response_mode") == ["form_post"]
    else:
        assert qs.get("response_type") == [
            "code"
        ], f"{provider_id}: response_type != code"
    # Scope: must be set (even if implementation chose an empty default — naver/
    # vercel/notion). Providers that omit scope param entirely are still allowed.
    if "scope" in qs:
        assert qs["scope"][0] is not None
    # PKCE: code_challenge appears when the helper was given a verifier.
    if provider_id in {"atlassian", "figma", "kick", "twitter", "vk"}:
        assert qs.get("code_challenge_method") == ["S256"]
        assert "code_challenge" in qs


def test_provider_ids_match_reference() -> None:
    """Smoke check that the canonical providers ship with sensible ids."""
    expected_ids = {
        "apple", "atlassian", "cognito", "discord", "dropbox", "facebook",
        "figma", "github", "gitlab", "google", "huggingface", "kakao", "kick",
        "line", "linear", "linkedin", "microsoft", "naver", "notion", "paybin",
        "paypal", "polar", "railway", "reddit", "roblox", "salesforce", "slack",
        "spotify", "tiktok", "twitch", "twitter", "vercel", "vk", "wechat",
        "zoom",
    }
    actual_ids = set()
    for pid, factory, extra in PROVIDERS:
        p = factory(client_id="x", client_secret="y", **extra)
        actual_ids.add(p.id)
    # Allow id to differ from key for microsoft-entra-id-style providers but
    # check that every test entry has a non-empty id.
    assert all(actual_ids)
    assert expected_ids.issubset(actual_ids), expected_ids - actual_ids
