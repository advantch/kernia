"""MockSAMLIdP signs assertions that python3-saml verifies in STRICT mode.

This is the round-trip the original Lane H deferred. The fixture's XML-DSIG
signatures are now built with libxml2-backed exclusive canonicalization (via
lxml), so a strict verifier reconstructs the same canonical bytes for both the
Reference digest and the SignedInfo signature.

We bypass the higher-level python3-saml `Auth` wrapper (which insists on a full
HTTP request stack) and call its low-level `OneLogin_Saml2_Response` directly
with strict + signature-required settings.
"""

from __future__ import annotations

import pytest

pytestmark = pytest.mark.filterwarnings("ignore::DeprecationWarning")


def _settings(idp, sp_entity: str, sp_acs: str):
    from onelogin.saml2.settings import OneLogin_Saml2_Settings

    raw = {
        "strict": True,
        "debug": False,
        "sp": {
            "entityId": sp_entity,
            "assertionConsumerService": {
                "url": sp_acs,
                "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
            },
            "NameIDFormat": "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
        },
        "idp": {
            "entityId": idp.entity_id,
            "singleSignOnService": {
                "url": idp.sso_url,
                "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
            },
            "x509cert": idp.cert_b64,
        },
        "security": {
            "wantAssertionsSigned": True,
            "wantMessagesSigned": False,
            "signatureAlgorithm": "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
            "digestAlgorithm": "http://www.w3.org/2001/04/xmlenc#sha256",
        },
    }
    return OneLogin_Saml2_Settings(raw, sp_validation_only=True, custom_base_path=None)


def test_python3_saml_strict_accepts_mock_idp_assertion() -> None:
    from kernia_test_utils import MockSAMLIdP
    from onelogin.saml2.response import OneLogin_Saml2_Response

    idp = MockSAMLIdP(entity_id="https://idp.example.com", sso_url="https://idp.example.com/sso")
    sp_acs = "https://sp.example.com/acs"
    sp_entity = "sp-strict"

    response_b64 = idp.create_assertion(
        name_id="alice@example.com",
        attrs={"email": "alice@example.com", "groups": ["admin"]},
        audience=sp_entity,
        recipient=sp_acs,
    )

    settings = _settings(idp, sp_entity=sp_entity, sp_acs=sp_acs)
    # `OneLogin_Saml2_Response` runs the full XML-DSIG verify when
    # `is_valid` is called with strict settings (which our settings declare).
    response = OneLogin_Saml2_Response(settings, response_b64)
    is_valid = response.is_valid(
        request_data={
            "https": "on",
            "http_host": "sp.example.com",
            "script_name": "/acs",
            "server_port": "443",
        }
    )
    assert is_valid is True, getattr(response, "_error", None) or "verification failed"

    # And we can pull the NameID + attributes back out.
    assert response.get_nameid() == "alice@example.com"
    attrs = response.get_attributes()
    assert attrs.get("email") == ["alice@example.com"]
    assert attrs.get("groups") == ["admin"]


def test_python3_saml_strict_rejects_wrong_cert() -> None:
    """If we tell the SP a different cert than the one that signed, strict mode
    must reject. Proves we're not accidentally trusting any signature."""
    from kernia_test_utils import MockSAMLIdP
    from onelogin.saml2.response import OneLogin_Saml2_Response

    real = MockSAMLIdP(entity_id="https://idp.example.com", sso_url="https://idp.example.com/sso")
    decoy = MockSAMLIdP(entity_id="https://idp.example.com", sso_url="https://idp.example.com/sso")

    response_b64 = real.create_assertion(
        name_id="alice@example.com",
        attrs={"email": "alice@example.com"},
        audience="sp-strict",
        recipient="https://sp.example.com/acs",
    )

    # SP configured with the WRONG IdP cert (the decoy's cert).
    decoy_for_settings = MockSAMLIdP.__new__(MockSAMLIdP)
    # Borrow only the cert; keep entity_id/sso_url so settings build cleanly.
    decoy_for_settings.entity_id = real.entity_id
    decoy_for_settings.sso_url = real.sso_url
    decoy_for_settings._cert = decoy._cert
    decoy_for_settings._key = decoy._key
    settings = _settings(
        decoy_for_settings, sp_entity="sp-strict", sp_acs="https://sp.example.com/acs"
    )
    response = OneLogin_Saml2_Response(settings, response_b64)
    is_valid = response.is_valid(
        request_data={
            "https": "on",
            "http_host": "sp.example.com",
            "script_name": "/acs",
            "server_port": "443",
        }
    )
    assert is_valid is False
