"""End-to-end SSO tests.

Three flows are exercised through the live ASGI app:

  1. OIDC sign-in via `MockIdP` — discovery / authorize / token exchange / id_token
     verification / userinfo. We splice the MockIdP's `httpx.MockTransport` into the
     plugin via `advanced["sso"]["http_transport"]` so the production code path
     uses the mock instead of a real network IdP.

  2. SAML sign-in via `MockSAMLIdP` — AuthnRequest construction, ACS validation,
     attribute mapping. SAML validation is in "permissive" mode for this test
     because `MockSAMLIdP` cannot produce a libxml2-canonicalized signature (see
     its docstring + `saml.validate_strict` for the trade-off). We still verify
     issuer / audience / NotBefore / NotOnOrAfter / InResponseTo / cert match /
     signature reference, and we explicitly test that the wrong-cert case is
     rejected.

  3. Email-domain → SSO routing — registering a verified SSO domain and then
     calling `/sign-in/email` returns a 200 `{redirect: ...}` payload instead of
     consuming the password.
"""

from __future__ import annotations

from urllib.parse import parse_qs, urlsplit

from better_auth.auth import init
from better_auth.plugins import email_and_password
from better_auth.types.init_options import BetterAuthOptions
from better_auth_memory_adapter import memory_adapter
from better_auth_sso import sso
from better_auth_test_utils import ASGIDriver, MockIdP, MockSAMLIdP

# ---------------------------------------------------------------------------
# OIDC end-to-end
# ---------------------------------------------------------------------------


def _make_oidc_driver(idp: MockIdP) -> ASGIDriver:
    auth = init(
        BetterAuthOptions(
            database=memory_adapter(),
            secret="test-secret-key",
            plugins=[sso(), email_and_password()],
            advanced={
                "sso": {
                    "disable_admin_check": True,
                    "http_transport": idp.mock_transport(),
                },
                "disable_csrf_check": True,
            },
            trusted_origins=["http://localhost:3000"],
        )
    )
    return ASGIDriver(app=auth.router.mount())


async def test_oidc_sign_in_end_to_end() -> None:
    idp = MockIdP(issuer="https://test-idp", audience="client-1")
    idp.create_user(sub="user-1", email="alice@acme.com", name="Alice Acme")
    driver = _make_oidc_driver(idp)

    # Register the OIDC provider.
    r = await driver.request(
        "POST",
        "/sso/register-provider",
        json_body={
            "issuer": "https://test-idp",
            "kind": "oidc",
            "name": "Test IdP",
            "domains": ["acme.com"],
            "oidcConfig": {
                "issuer": "https://test-idp",
                "clientId": "client-1",
                "clientSecret": "secret",
                "scopes": ["openid", "email", "profile"],
            },
            "mapping": {"email": "email", "name": "name"},
        },
    )
    assert r.status == 200, r.json()
    provider_id = r.json()["provider"]["id"]

    # GET /sso/oidc/sign-in/<id> — should redirect to the IdP authorize endpoint.
    r = await driver.request("GET", f"/sso/oidc/sign-in/{provider_id}")
    assert r.status == 302
    location = dict(r.headers)["location"]
    parsed = urlsplit(location)
    assert parsed.netloc == "test-idp"
    qs = parse_qs(parsed.query)
    state = qs["state"][0]
    assert qs["redirect_uri"][0]
    assert qs["client_id"] == ["client-1"]

    # Skip the actual IdP login UI; jump straight to the token-exchange code.
    # MockIdP doesn't issue a code on /authorize — it expects the SP to POST to
    # /token with any code at all and returns the next-queued user. We mimic the
    # IdP-issued code as a free-form value here.
    r = await driver.request(
        "GET",
        f"/sso/oidc/callback/{provider_id}",
        query=f"state={state}&code=mock-code",
    )
    assert r.status == 200, r.json()
    body = r.json()
    assert body["user"]["email"] == "alice@acme.com"
    assert body["user"]["name"] == "Alice Acme"
    # Session cookie is set.
    assert "better-auth.session_token" in driver.cookies

    # /get-session reflects the new session.
    r = await driver.request("GET", "/get-session")
    assert r.status == 200
    assert r.json()["user"]["email"] == "alice@acme.com"


async def test_oidc_callback_rejects_bad_state() -> None:
    idp = MockIdP(issuer="https://test-idp", audience="client-1")
    driver = _make_oidc_driver(idp)
    r = await driver.request(
        "POST",
        "/sso/register-provider",
        json_body={
            "issuer": "https://test-idp",
            "kind": "oidc",
            "oidcConfig": {
                "issuer": "https://test-idp",
                "clientId": "client-1",
                "clientSecret": "secret",
            },
        },
    )
    provider_id = r.json()["provider"]["id"]
    r = await driver.request(
        "GET",
        f"/sso/oidc/callback/{provider_id}",
        query="state=bogus&code=anything",
    )
    assert r.status == 400
    assert r.json()["code"] == "SSO_OIDC_STATE_INVALID"


# ---------------------------------------------------------------------------
# SAML end-to-end
# ---------------------------------------------------------------------------


def _make_saml_driver() -> ASGIDriver:
    auth = init(
        BetterAuthOptions(
            database=memory_adapter(),
            secret="test-secret-key",
            base_url="http://localhost:3000",
            plugins=[sso(), email_and_password()],
            advanced={
                "sso": {
                    "disable_admin_check": True,
                    # Strict XML-DSIG validation now works against MockSAMLIdP
                    # since the fixture canonicalizes via lxml exc-c14n.
                    "saml_validation": "strict",
                },
                "disable_csrf_check": True,
            },
        )
    )
    return ASGIDriver(app=auth.router.mount())


async def _register_saml_provider(
    driver: ASGIDriver, idp: MockSAMLIdP, provider_name: str = "test"
) -> str:
    """Register a SAML provider that talks to `idp`. Returns provider id."""
    r = await driver.request(
        "POST",
        "/sso/register-provider",
        json_body={
            "issuer": idp.entity_id,
            "kind": "saml",
            "name": provider_name,
            "samlConfig": {
                "sp": {
                    "entityId": "http://localhost:3000/sso/sp",
                    # acsUrl/sloUrl default from base_url.
                },
                "idp": {
                    "entityId": idp.entity_id,
                    "ssoUrl": idp.sso_url,
                    "cert": idp.cert_pem,
                },
                "wantAssertionsSigned": True,
            },
            "mapping": {"email": "EmailAddress", "name": "DisplayName"},
        },
    )
    assert r.status == 200, r.json()
    return r.json()["provider"]["id"]


async def test_saml_sign_in_end_to_end() -> None:
    idp = MockSAMLIdP(
        entity_id="https://idp.test.example",
        sso_url="https://idp.test.example/sso",
    )
    driver = _make_saml_driver()
    provider_id = await _register_saml_provider(driver, idp)

    # AuthnRequest construction: GET /sso/saml/sign-in returns 302 to the IdP.
    r = await driver.request("GET", f"/sso/saml/sign-in/{provider_id}")
    assert r.status == 302
    location = dict(r.headers)["location"]
    assert location.startswith("https://idp.test.example/sso?SAMLRequest=")

    # Simulate the IdP signing an assertion and POSTing back to ACS.
    sp_entity = "http://localhost:3000/sso/sp"
    acs_url = f"http://localhost:3000/sso/saml/acs/{provider_id}"
    saml_response = idp.create_assertion(
        name_id="alice@acme.com",
        attrs={"EmailAddress": "alice@acme.com", "DisplayName": "Alice Acme"},
        audience=sp_entity,
        recipient=acs_url,
    )

    r = await driver.request(
        "POST",
        f"/sso/saml/acs/{provider_id}",
        json_body={"SAMLResponse": saml_response, "RelayState": "/dashboard"},
    )
    assert r.status == 200, r.json()
    body = r.json()
    assert body["user"]["email"] == "alice@acme.com"
    assert body["user"]["name"] == "Alice Acme"
    assert body["redirect"] == "/dashboard"
    assert "better-auth.session_token" in driver.cookies


async def test_saml_acs_rejects_wrong_cert() -> None:
    """An assertion signed by a different IdP should fail cert-match."""
    idp_good = MockSAMLIdP(
        entity_id="https://good.idp.example", sso_url="https://good.idp.example/sso"
    )
    idp_evil = MockSAMLIdP(
        entity_id="https://good.idp.example", sso_url="https://good.idp.example/sso"
    )
    driver = _make_saml_driver()
    provider_id = await _register_saml_provider(driver, idp_good)

    sp_entity = "http://localhost:3000/sso/sp"
    acs_url = f"http://localhost:3000/sso/saml/acs/{provider_id}"
    # idp_evil signs an assertion claiming to be from the good entity.
    saml_response = idp_evil.create_assertion(
        name_id="attacker@acme.com",
        attrs={"EmailAddress": "attacker@acme.com"},
        audience=sp_entity,
        recipient=acs_url,
    )
    r = await driver.request(
        "POST",
        f"/sso/saml/acs/{provider_id}",
        json_body={"SAMLResponse": saml_response},
    )
    assert r.status == 400
    assert r.json()["code"] == "SSO_SAML_RESPONSE_INVALID"


async def test_saml_metadata_returned() -> None:
    idp = MockSAMLIdP()
    driver = _make_saml_driver()
    provider_id = await _register_saml_provider(driver, idp)

    r = await driver.request("GET", f"/sso/saml/metadata/{provider_id}")
    assert r.status == 200
    body = r.json()
    assert "EntityDescriptor" in body["metadata"]
    assert f"/sso/saml/acs/{provider_id}" in body["metadata"]


# ---------------------------------------------------------------------------
# Domain → provider routing on /sign-in/email
# ---------------------------------------------------------------------------


async def test_email_signin_redirects_to_sso_when_domain_is_verified() -> None:
    """Sign-in with a password should be hijacked into an SSO redirect."""
    auth = init(
        BetterAuthOptions(
            database=memory_adapter(),
            secret="test-secret-key",
            base_url="http://localhost:3000",
            plugins=[sso(), email_and_password()],
            advanced={
                "sso": {"disable_admin_check": True},
                "disable_csrf_check": True,
            },
        )
    )
    driver = ASGIDriver(app=auth.router.mount())

    # Register provider + domain.
    r = await driver.request(
        "POST",
        "/sso/register-provider",
        json_body={
            "issuer": "https://acme-idp",
            "kind": "oidc",
            "oidcConfig": {
                "issuer": "https://acme-idp",
                "clientId": "x",
                "clientSecret": "y",
            },
        },
    )
    provider_id = r.json()["provider"]["id"]
    r = await driver.request(
        "POST",
        "/sso/register-domain",
        json_body={"ssoProviderId": provider_id, "domain": "acme.com"},
    )
    token = r.json()["token"]
    r = await driver.request(
        "POST",
        "/sso/verify-domain",
        json_body={"domain": "acme.com", "token": token},
    )
    assert r.status == 200 and r.json()["verified"] is True

    # Now `/sign-in/email` with an acme.com email should return a redirect.
    r = await driver.request(
        "POST",
        "/sign-in/email",
        json_body={"email": "bob@acme.com", "password": "irrelevant"},
    )
    assert r.status == 200
    body = r.json()
    assert body["code"] == "SSO_REDIRECT"
    assert body["redirect"].endswith(f"/sso/oidc/sign-in/{provider_id}")
    assert body["providerId"] == provider_id


async def test_email_signin_passes_through_for_unmatched_domain() -> None:
    auth = init(
        BetterAuthOptions(
            database=memory_adapter(),
            secret="test-secret-key",
            plugins=[sso(), email_and_password()],
            advanced={"sso": {"disable_admin_check": True}, "disable_csrf_check": True},
        )
    )
    driver = ASGIDriver(app=auth.router.mount())
    # Sign-in attempts on an unknown domain still hit the normal path (and fail
    # because the user doesn't exist).
    r = await driver.request(
        "POST",
        "/sign-in/email",
        json_body={"email": "nobody@unknown.test", "password": "irrelevant"},
    )
    assert r.status in (401, 404), r.json()
    # Not an SSO redirect.
    assert r.json().get("code") != "SSO_REDIRECT"
