"""Unit tests for attribute mapping.

Covers both `oidc.apply_mapping` (claim dict → user fields) and
`saml.apply_mapping` (SAML AttributeStatement → user fields).
"""

from __future__ import annotations

from better_auth_sso.oidc import apply_mapping as apply_oidc_mapping
from better_auth_sso.saml import SAMLAssertion, apply_mapping as apply_saml_mapping


def test_oidc_mapping_pulls_named_claims() -> None:
    claims = {
        "sub": "u1",
        "email": "alice@acme.com",
        "displayName": "Alice Acme",
        "picture": "https://cdn/p.png",
    }
    mapping = {"email": "email", "name": "displayName", "image": "picture"}
    out = apply_oidc_mapping(claims, mapping)
    assert out == {
        "email": "alice@acme.com",
        "name": "Alice Acme",
        "image": "https://cdn/p.png",
    }


def test_oidc_mapping_drops_missing_sources() -> None:
    claims = {"sub": "u1", "email": "a@b.c"}
    mapping = {"email": "email", "name": "displayName"}
    out = apply_oidc_mapping(claims, mapping)
    assert out == {"email": "a@b.c"}


def test_oidc_default_mapping_when_none() -> None:
    claims = {
        "sub": "u1",
        "email": "x@y.z",
        "name": "X",
        "email_verified": True,
        "picture": "p",
        "ignored": "extra",
    }
    out = apply_oidc_mapping(claims, None)
    assert out == {
        "sub": "u1",
        "email": "x@y.z",
        "name": "X",
        "email_verified": True,
        "picture": "p",
    }


def test_saml_mapping_uses_attributes() -> None:
    assertion = SAMLAssertion(
        name_id="alice@acme.com",
        attributes={"EmailAddress": "alice@acme.com", "DisplayName": "Alice"},
    )
    out = apply_saml_mapping(assertion, {"email": "EmailAddress", "name": "DisplayName"})
    assert out["email"] == "alice@acme.com"
    assert out["name"] == "Alice"


def test_saml_mapping_falls_back_to_name_id_for_email() -> None:
    assertion = SAMLAssertion(name_id="bob@acme.com", attributes={})
    out = apply_saml_mapping(assertion, None)
    assert out["email"] == "bob@acme.com"
    assert out["sub"] == "bob@acme.com"


def test_saml_mapping_skips_email_fallback_when_name_id_not_email() -> None:
    assertion = SAMLAssertion(name_id="u-12345", attributes={"mail": "z@y.x"})
    out = apply_saml_mapping(assertion, {"email": "mail"})
    assert out["email"] == "z@y.x"
    assert out["sub"] == "u-12345"
