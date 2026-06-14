"""SSO provider read/update/delete endpoint parity.

Ports the portable subset of `reference/packages/sso/src/providers.test.ts` to the
Python SSO plugin — the cases that exercise ownership-gated access control,
response sanitization (masked client id, parsed certificate, no secret leakage),
and update/delete validation.

Ownership model (mirrors upstream): the user who registers a provider owns it
(`ssoProvider.userId`). A provider with no `organizationId` is accessible only to
its owner; the read endpoints (`/sso/get-provider`, `/sso/providers`) and the
sanitized projection never surface the OIDC `clientSecret` or the raw SAML
certificate PEM.

These run through the live ASGI app so the session/auth wiring is exercised end
to end. `disable_admin_check` is enabled so registration is allowed for any
authenticated user (admin RBAC is a separate, deployment-supplied concern), but
the *authenticated session* is still required and is what stamps `userId` onto
the provider row.
"""

from __future__ import annotations

from kernia.auth import init
from kernia.plugins import email_and_password
from kernia.types.init_options import KerniaOptions
from kernia_memory_adapter import memory_adapter
from kernia_sso import sso
from kernia_test_utils import ASGIDriver, MockSAMLIdP

_SESSION_COOKIE = "better-auth.session_token"


def _build() -> ASGIDriver:
    auth = init(
        KerniaOptions(
            database=memory_adapter(),
            secret="test-secret-key",
            base_url="http://localhost:3000",
            plugins=[sso(), email_and_password()],
            advanced={
                "sso": {"disable_admin_check": True},
                "disable_csrf_check": True,
            },
            trusted_origins=["http://localhost:3000"],
        )
    )
    return ASGIDriver(app=auth.router.mount())


async def _signup(driver: ASGIDriver, email: str) -> None:
    r = await driver.request(
        "POST",
        "/sign-up/email",
        json_body={"email": email, "password": "passpass1", "name": "T"},
    )
    assert r.status == 200, r.json()
    assert _SESSION_COOKIE in driver.cookies


async def _register_oidc(
    driver: ASGIDriver,
    *,
    issuer: str = "https://idp.example.com",
    client_id: str = "client-abcd1234",
    client_secret: str = "super-secret-value",
) -> str:
    r = await driver.request(
        "POST",
        "/sso/register-provider",
        json_body={
            "issuer": issuer,
            "kind": "oidc",
            "name": "OIDC",
            "oidcConfig": {
                "issuer": issuer,
                "clientId": client_id,
                "clientSecret": client_secret,
                "pkce": True,
                "scopes": ["openid", "email"],
            },
        },
    )
    assert r.status == 200, r.json()
    return r.json()["provider"]["id"]


async def _register_saml(driver: ASGIDriver, *, cert: str | None = None) -> str:
    idp = MockSAMLIdP()
    r = await driver.request(
        "POST",
        "/sso/register-provider",
        json_body={
            "issuer": "https://saml-idp.example.com",
            "kind": "saml",
            "name": "SAML",
            "samlConfig": {
                "idp": {
                    "entityId": idp.entity_id,
                    "ssoUrl": idp.sso_url,
                    "cert": cert if cert is not None else idp.cert_pem,
                },
                "sp": {
                    "entityId": "http://localhost:3000/sso/sp",
                    "acsUrl": "http://localhost:3000/sso/acs",
                    "audience": "http://localhost:3000/sso/sp",
                },
                "wantAssertionsSigned": True,
                "signatureAlgorithm": "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
                "digestAlgorithm": "http://www.w3.org/2001/04/xmlenc#sha256",
            },
        },
    )
    assert r.status == 200, r.json()
    return r.json()["provider"]["id"]


# ---------------------------------------------------------------------------
# GET /sso/get-provider
# ---------------------------------------------------------------------------


async def test_get_provider_401_when_not_authenticated() -> None:
    driver = _build()
    await _signup(driver, "owner@example.com")
    pid = await _register_oidc(driver)
    driver.cookies.clear()
    r = await driver.request("GET", "/sso/get-provider", query=f"providerId={pid}")
    assert r.status == 401


async def test_get_provider_404_when_not_found() -> None:
    driver = _build()
    await _signup(driver, "owner@example.com")
    r = await driver.request("GET", "/sso/get-provider", query="providerId=does-not-exist")
    assert r.status == 404


async def test_get_provider_403_when_not_owner() -> None:
    driver = _build()
    await _signup(driver, "alice@example.com")
    pid = await _register_oidc(driver)
    # Switch to a different user.
    driver.cookies.clear()
    await _signup(driver, "bob@example.com")
    r = await driver.request("GET", "/sso/get-provider", query=f"providerId={pid}")
    assert r.status == 403


async def test_get_provider_oidc_masks_client_id() -> None:
    driver = _build()
    await _signup(driver, "owner@example.com")
    pid = await _register_oidc(driver, client_id="client-abcd1234")
    r = await driver.request("GET", "/sso/get-provider", query=f"providerId={pid}")
    assert r.status == 200
    body = r.json()
    assert body["type"] == "oidc"
    assert body["oidcConfig"]["clientIdLastFour"] == "****1234"


async def test_get_provider_does_not_leak_client_secret() -> None:
    driver = _build()
    await _signup(driver, "owner@example.com")
    pid = await _register_oidc(driver, client_secret="top-secret")
    r = await driver.request("GET", "/sso/get-provider", query=f"providerId={pid}")
    assert r.status == 200
    # No serialized representation may contain the secret, anywhere.
    assert "top-secret" not in r.body.decode("utf-8")
    assert "clientSecret" not in r.json()["oidcConfig"]


async def test_get_provider_masks_short_client_id() -> None:
    driver = _build()
    await _signup(driver, "owner@example.com")
    pid = await _register_oidc(driver, client_id="ab")
    r = await driver.request("GET", "/sso/get-provider", query=f"providerId={pid}")
    assert r.status == 200
    assert r.json()["oidcConfig"]["clientIdLastFour"] == "****"


async def test_get_provider_saml_parses_certificate_not_raw_pem() -> None:
    driver = _build()
    await _signup(driver, "owner@example.com")
    pid = await _register_saml(driver)
    r = await driver.request("GET", "/sso/get-provider", query=f"providerId={pid}")
    assert r.status == 200
    body = r.json()
    assert body["type"] == "saml"
    cert = body["samlConfig"]["certificate"]
    # Parsed metadata is surfaced; the raw PEM body is not.
    assert "fingerprintSha256" in cert
    assert "publicKeyAlgorithm" in cert
    assert "-----BEGIN CERTIFICATE-----" not in r.body.decode("utf-8")


async def test_get_provider_saml_cert_parse_error_graceful() -> None:
    driver = _build()
    await _signup(driver, "owner@example.com")
    pid = await _register_saml(driver, cert="not-a-real-certificate")
    r = await driver.request("GET", "/sso/get-provider", query=f"providerId={pid}")
    assert r.status == 200
    assert r.json()["samlConfig"]["certificate"] == {"error": "Failed to parse certificate"}


# ---------------------------------------------------------------------------
# GET /sso/providers (accessible list)
# ---------------------------------------------------------------------------


async def test_providers_401_when_not_authenticated() -> None:
    driver = _build()
    r = await driver.request("GET", "/sso/providers")
    assert r.status == 401


async def test_providers_returns_only_owned() -> None:
    driver = _build()
    await _signup(driver, "alice@example.com")
    await _register_oidc(driver, issuer="https://a.example.com", client_id="c-aaaa1111")
    r = await driver.request("GET", "/sso/providers")
    assert r.status == 200
    assert len(r.json()["providers"]) == 1

    # A different user sees none of alice's providers.
    driver.cookies.clear()
    await _signup(driver, "bob@example.com")
    r = await driver.request("GET", "/sso/providers")
    assert r.status == 200
    assert r.json()["providers"] == []


# ---------------------------------------------------------------------------
# POST /sso/update-provider
# ---------------------------------------------------------------------------


async def test_update_404_when_not_found() -> None:
    driver = _build()
    await _signup(driver, "owner@example.com")
    r = await driver.request(
        "POST", "/sso/update-provider", json_body={"id": "missing", "name": "x"}
    )
    assert r.status == 404


async def test_update_400_when_no_fields() -> None:
    driver = _build()
    await _signup(driver, "owner@example.com")
    pid = await _register_oidc(driver)
    r = await driver.request("POST", "/sso/update-provider", json_body={"id": pid})
    assert r.status == 400


async def test_update_400_saml_config_on_oidc_provider() -> None:
    driver = _build()
    await _signup(driver, "owner@example.com")
    pid = await _register_oidc(driver)
    r = await driver.request(
        "POST",
        "/sso/update-provider",
        json_body={"id": pid, "samlConfig": {"idp": {"cert": "x"}}},
    )
    assert r.status == 400


async def test_update_400_oidc_config_on_saml_provider() -> None:
    driver = _build()
    await _signup(driver, "owner@example.com")
    pid = await _register_saml(driver)
    r = await driver.request(
        "POST",
        "/sso/update-provider",
        json_body={"id": pid, "oidcConfig": {"clientId": "x"}},
    )
    assert r.status == 400


async def test_update_issuer() -> None:
    driver = _build()
    await _signup(driver, "owner@example.com")
    pid = await _register_oidc(driver, issuer="https://old.example.com")
    r = await driver.request(
        "POST",
        "/sso/update-provider",
        json_body={"id": pid, "issuer": "https://new.example.com"},
    )
    assert r.status == 200
    assert r.json()["provider"]["issuer"] == "https://new.example.com"


async def test_update_400_invalid_issuer_url() -> None:
    driver = _build()
    await _signup(driver, "owner@example.com")
    pid = await _register_oidc(driver)
    r = await driver.request(
        "POST",
        "/sso/update-provider",
        json_body={"id": pid, "issuer": "not-a-valid-url"},
    )
    assert r.status == 400


async def test_update_partial_oidc_config_merges() -> None:
    driver = _build()
    await _signup(driver, "owner@example.com")
    pid = await _register_oidc(driver, client_id="keep-me-9999")
    r = await driver.request(
        "POST",
        "/sso/update-provider",
        json_body={"id": pid, "oidcConfig": {"scopes": ["openid", "profile"]}},
    )
    assert r.status == 200
    cfg = r.json()["provider"]["oidcConfig"]
    # Partial update preserves the untouched clientId and applies the new scopes.
    assert cfg["clientId"] == "keep-me-9999"
    assert cfg["scopes"] == ["openid", "profile"]


# ---------------------------------------------------------------------------
# POST /sso/delete-provider
# ---------------------------------------------------------------------------


async def test_delete_404_when_not_found() -> None:
    driver = _build()
    await _signup(driver, "owner@example.com")
    r = await driver.request("POST", "/sso/delete-provider", json_body={"id": "missing"})
    assert r.status == 404


async def test_delete_provider_successfully() -> None:
    driver = _build()
    await _signup(driver, "owner@example.com")
    pid = await _register_oidc(driver)
    r = await driver.request("POST", "/sso/delete-provider", json_body={"id": pid})
    assert r.status == 200
    assert r.json()["success"] is True
    # Now unreachable.
    r = await driver.request("GET", "/sso/get-provider", query=f"providerId={pid}")
    assert r.status == 404
