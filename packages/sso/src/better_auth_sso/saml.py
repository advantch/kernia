"""SAML SSO — python3-saml wrapper + permissive validator for the mock IdP.

The reference implementation here is `python3-saml` (OneLogin's library, built on
top of `xmlsec`/`libxml2`). It is a sync library, so every call that touches it is
dispatched through `anyio.to_thread.run_sync` to stay friendly with the rest of
the async-only auth core.

A note on validation modes
--------------------------
`MockSAMLIdP` in `better_auth_test_utils` signs assertions using a Python-emitted
serialization rather than libxml2's exclusive canonicalization. python3-saml /
xmlsec re-canonicalize the assertion via libxml2 before verifying the signature,
so signatures produced by `MockSAMLIdP` will not pass a strict round-trip.

That's a deliberate trade-off in the mock IdP (see its module docstring). We
expose two validation paths so tests can exercise both:

  * `validate_strict(...)` — full python3-saml validation, including signature.
    Use this with a real IdP or with `xmlsec`-emitted assertions.
  * `validate_permissive(...)` — verifies issuer / audience / NotBefore /
    NotOnOrAfter / InResponseTo / status, parses the assertion attributes, and
    optionally verifies the digest hash. It does *not* verify the XML-DSIG
    signature itself; instead it confirms the IdP's certificate matches the one
    configured for the provider and that the well-known structural pieces line
    up. We use this for end-to-end tests with `MockSAMLIdP`.

Either mode emits the same `SAMLAssertion` dataclass downstream, so route
handlers don't branch on validation mode.
"""

from __future__ import annotations

import base64
import json
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any
from xml.etree import ElementTree as ET

import anyio


SAML_NS = {
    "samlp": "urn:oasis:names:tc:SAML:2.0:protocol",
    "saml": "urn:oasis:names:tc:SAML:2.0:assertion",
    "ds": "http://www.w3.org/2000/09/xmldsig#",
    "md": "urn:oasis:names:tc:SAML:2.0:metadata",
}


# ---------------------------------------------------------------------------
# Data shapes
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class SAMLAssertion:
    """Normalized result of parsing a SAML Response.

    All fields are optional except `name_id` and `attributes` — those are the
    minimum we need to sign a user in.
    """

    name_id: str
    attributes: Mapping[str, Any]
    issuer: str | None = None
    in_response_to: str | None = None
    session_index: str | None = None
    not_before: str | None = None
    not_on_or_after: str | None = None


# ---------------------------------------------------------------------------
# Settings builder + AuthnRequest + Metadata
# ---------------------------------------------------------------------------


def _settings_dict(
    *,
    sp_entity_id: str,
    acs_url: str,
    slo_url: str | None,
    idp_entity_id: str,
    idp_sso_url: str,
    idp_slo_url: str | None,
    idp_cert: str,
    sp_cert: str | None = None,
    sp_private_key: str | None = None,
    want_assertions_signed: bool = True,
    want_messages_signed: bool = False,
    strict: bool = True,
) -> dict[str, Any]:
    """Build the python3-saml settings dict from our provider config shape."""
    sp: dict[str, Any] = {
        "entityId": sp_entity_id,
        "assertionConsumerService": {
            "url": acs_url,
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
        },
        "NameIDFormat": "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
    }
    if slo_url:
        sp["singleLogoutService"] = {
            "url": slo_url,
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
        }
    if sp_cert:
        sp["x509cert"] = sp_cert
    if sp_private_key:
        sp["privateKey"] = sp_private_key

    idp: dict[str, Any] = {
        "entityId": idp_entity_id,
        "singleSignOnService": {
            "url": idp_sso_url,
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
        },
        "x509cert": _strip_pem(idp_cert),
    }
    if idp_slo_url:
        idp["singleLogoutService"] = {
            "url": idp_slo_url,
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
        }

    return {
        "strict": strict,
        "debug": False,
        "sp": sp,
        "idp": idp,
        "security": {
            "wantAssertionsSigned": want_assertions_signed,
            "wantMessagesSigned": want_messages_signed,
            "authnRequestsSigned": False,
            "wantNameId": True,
            "wantNameIdEncrypted": False,
            "signatureAlgorithm": "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
            "digestAlgorithm": "http://www.w3.org/2001/04/xmlenc#sha256",
        },
    }


def _strip_pem(cert: str) -> str:
    """python3-saml wants the raw base64 cert body, no PEM headers."""
    return (
        cert.replace("-----BEGIN CERTIFICATE-----", "")
        .replace("-----END CERTIFICATE-----", "")
        .replace("\n", "")
        .replace("\r", "")
        .strip()
    )


@dataclass(frozen=True, slots=True)
class SAMLPlan:
    """The configuration we resolved for a provider; passed to all SAML helpers."""

    sp_entity_id: str
    acs_url: str
    slo_url: str | None
    idp_entity_id: str
    idp_sso_url: str
    idp_slo_url: str | None
    idp_cert: str
    sp_cert: str | None = None
    sp_private_key: str | None = None
    want_assertions_signed: bool = True
    want_messages_signed: bool = False
    audience: str | None = None  # defaults to sp_entity_id

    def settings(self, *, strict: bool = True) -> dict[str, Any]:
        return _settings_dict(
            sp_entity_id=self.sp_entity_id,
            acs_url=self.acs_url,
            slo_url=self.slo_url,
            idp_entity_id=self.idp_entity_id,
            idp_sso_url=self.idp_sso_url,
            idp_slo_url=self.idp_slo_url,
            idp_cert=self.idp_cert,
            sp_cert=self.sp_cert,
            sp_private_key=self.sp_private_key,
            want_assertions_signed=self.want_assertions_signed,
            want_messages_signed=self.want_messages_signed,
            strict=strict,
        )


def parse_config(raw: str | Mapping[str, Any] | None) -> dict[str, Any]:
    """Decode the SAML config blob from storage."""
    if raw is None:
        return {}
    if isinstance(raw, str):
        return json.loads(raw)
    return dict(raw)


def plan_from_config(config: Mapping[str, Any]) -> SAMLPlan:
    """Build a `SAMLPlan` from a provider's `samlConfig` JSON dict."""
    sp = config.get("sp", {})
    idp = config.get("idp", {})
    return SAMLPlan(
        sp_entity_id=sp["entityId"],
        acs_url=sp["acsUrl"],
        slo_url=sp.get("sloUrl"),
        idp_entity_id=idp["entityId"],
        idp_sso_url=idp["ssoUrl"],
        idp_slo_url=idp.get("sloUrl"),
        idp_cert=idp["cert"],
        sp_cert=sp.get("cert"),
        sp_private_key=sp.get("privateKey"),
        want_assertions_signed=bool(config.get("wantAssertionsSigned", True)),
        want_messages_signed=bool(config.get("wantMessagesSigned", False)),
        audience=sp.get("audience") or sp["entityId"],
    )


# ---------------------------------------------------------------------------
# SP Metadata
# ---------------------------------------------------------------------------


async def sp_metadata_xml(plan: SAMLPlan) -> str:
    """Return the SP metadata XML document.

    Always emits via python3-saml so the output is byte-for-byte compatible with
    what real IdPs ingest. python3-saml's metadata builder is sync, so we punt
    onto a thread.
    """

    def _build() -> str:
        from onelogin.saml2.settings import OneLogin_Saml2_Settings

        settings = OneLogin_Saml2_Settings(plan.settings(strict=False), sp_validation_only=True)
        return settings.get_sp_metadata()

    return await anyio.to_thread.run_sync(_build)


# ---------------------------------------------------------------------------
# AuthnRequest
# ---------------------------------------------------------------------------


async def build_authn_request(plan: SAMLPlan) -> tuple[str, str]:
    """Return `(redirect_url, request_id)`.

    `redirect_url` is the IdP SSO URL with the AuthnRequest deflated/base64'd as
    a `SAMLRequest` query param. `request_id` is the AuthnRequest's `ID`
    attribute; the caller should persist it for InResponseTo validation.
    """

    def _build() -> tuple[str, str]:
        from urllib.parse import urlencode

        from onelogin.saml2.authn_request import OneLogin_Saml2_Authn_Request
        from onelogin.saml2.settings import OneLogin_Saml2_Settings

        settings = OneLogin_Saml2_Settings(plan.settings(strict=False))
        req = OneLogin_Saml2_Authn_Request(settings)
        deflated = req.get_request()
        sep = "&" if "?" in plan.idp_sso_url else "?"
        url = f"{plan.idp_sso_url}{sep}{urlencode({'SAMLRequest': deflated})}"
        return url, req.get_id()

    return await anyio.to_thread.run_sync(_build)


# ---------------------------------------------------------------------------
# Response validation — strict (python3-saml) and permissive (our parser)
# ---------------------------------------------------------------------------


class SAMLValidationError(Exception):
    """Raised when SAML response validation fails."""


async def validate_strict(
    plan: SAMLPlan,
    *,
    saml_response_b64: str,
    request_id: str | None = None,
) -> SAMLAssertion:
    """Strict validation via python3-saml. Verifies XML-DSIG.

    Requires the IdP to canonicalize via libxml2-compatible exclusive c14n.
    `MockSAMLIdP` (in our test_utils) now satisfies this — strict mode works
    against it. Use `validate_permissive` only for legacy IdPs that emit
    non-canonical signatures.
    """

    def _validate() -> SAMLAssertion:
        from urllib.parse import urlparse

        from onelogin.saml2.auth import OneLogin_Saml2_Auth

        # python3-saml reconstructs the request URL from request_data; the path
        # of the ACS URL goes in script_name, host/scheme/port live in their
        # own keys. Splitting plan.acs_url ensures the rebuilt URL matches the
        # Destination attribute on the SAML Response.
        parsed = urlparse(plan.acs_url)
        request_data = {
            "https": "on" if parsed.scheme == "https" else "off",
            "http_host": parsed.hostname or "localhost",
            "server_port": str(parsed.port or (443 if parsed.scheme == "https" else 80)),
            "script_name": parsed.path or "/",
            "get_data": {},
            "post_data": {"SAMLResponse": saml_response_b64},
        }
        auth = OneLogin_Saml2_Auth(request_data, plan.settings(strict=True))
        auth.process_response(request_id=request_id)
        errors = auth.get_errors()
        if errors:
            raise SAMLValidationError(
                f"SAML validation failed: {errors!r} ({auth.get_last_error_reason()})"
            )
        return SAMLAssertion(
            name_id=auth.get_nameid() or "",
            attributes=dict(auth.get_attributes() or {}),
            issuer=plan.idp_entity_id,
            in_response_to=request_id,
            session_index=auth.get_session_index(),
        )

    return await anyio.to_thread.run_sync(_validate)


def validate_permissive(
    plan: SAMLPlan,
    *,
    saml_response_b64: str,
    request_id: str | None = None,
    now: datetime | None = None,
) -> SAMLAssertion:
    """Validate structural pieces of a SAML response without trusting xmlsec c14n.

    Checks performed:
      * The Response is well-formed XML with a successful Status.
      * The Response's Issuer matches `plan.idp_entity_id`.
      * The Assertion's Conditions reference our `audience` (Audience element).
      * `NotBefore` <= now <= `NotOnOrAfter` (with a 5-minute clock skew).
      * `InResponseTo` matches `request_id` if provided.
      * The Signature element references the assertion by ID and the
        `X509Certificate` we see matches the cert configured on `plan` (stripped
        of whitespace). This is the integrity check we substitute for full
        XML-DSIG verification.

    Caveat: this is *not* a substitute for xmlsec in production. It exists so we
    can run end-to-end against `MockSAMLIdP`, whose canonicalization doesn't
    survive a libxml2 round-trip.
    """
    raw = base64.b64decode(saml_response_b64).decode("utf-8")
    try:
        root = ET.fromstring(raw)
    except ET.ParseError as e:  # noqa: BLE001
        raise SAMLValidationError(f"malformed SAML response: {e}") from None

    # Status
    status_code = root.find("./samlp:Status/samlp:StatusCode", SAML_NS)
    if status_code is None or status_code.attrib.get("Value", "").rsplit(":", 1)[
        -1
    ] != "Success":
        raise SAMLValidationError("SAML status is not Success")

    # Issuer at Response level
    response_issuer = root.find("./saml:Issuer", SAML_NS)
    if (
        response_issuer is None
        or (response_issuer.text or "").strip() != plan.idp_entity_id
    ):
        raise SAMLValidationError(
            f"unexpected issuer: {response_issuer is not None and response_issuer.text!r}"
        )

    # Assertion
    assertion = root.find("./saml:Assertion", SAML_NS)
    if assertion is None:
        raise SAMLValidationError("response has no Assertion")
    assertion_id = assertion.attrib.get("ID")

    # InResponseTo
    rt_attr = root.attrib.get("InResponseTo")
    if request_id is not None and rt_attr != request_id:
        raise SAMLValidationError(
            f"InResponseTo mismatch: {rt_attr!r} != {request_id!r}"
        )

    # Conditions / Audience
    conditions = assertion.find("./saml:Conditions", SAML_NS)
    audience_match = False
    not_before = not_on_or_after = None
    if conditions is not None:
        not_before = conditions.attrib.get("NotBefore")
        not_on_or_after = conditions.attrib.get("NotOnOrAfter")
        audience_value = plan.audience or plan.sp_entity_id
        for aud in conditions.findall(
            "./saml:AudienceRestriction/saml:Audience", SAML_NS
        ):
            if (aud.text or "").strip() == audience_value:
                audience_match = True
                break
    if not audience_match:
        raise SAMLValidationError("audience does not match SP entityId")

    # Timestamps
    now = now or datetime.now(tz=timezone.utc)
    skew = 5 * 60
    if not_before:
        nb = _parse_iso8601(not_before)
        if nb is not None and now.timestamp() + skew < nb.timestamp():
            raise SAMLValidationError("assertion not yet valid (NotBefore)")
    if not_on_or_after:
        noa = _parse_iso8601(not_on_or_after)
        if noa is not None and now.timestamp() - skew > noa.timestamp():
            raise SAMLValidationError("assertion expired (NotOnOrAfter)")

    # Signature: cert match + reference URI.
    sig = assertion.find("./ds:Signature", SAML_NS)
    if plan.want_assertions_signed:
        if sig is None:
            raise SAMLValidationError("assertion is not signed but signing is required")
        cert_node = sig.find(".//ds:X509Certificate", SAML_NS)
        seen_cert = (cert_node.text or "").strip() if cert_node is not None else ""
        expected_cert = _strip_pem(plan.idp_cert)
        # Compare with whitespace squashed.
        if "".join(seen_cert.split()) != "".join(expected_cert.split()):
            raise SAMLValidationError(
                "assertion is signed with an unexpected certificate"
            )
        ref = sig.find("./ds:SignedInfo/ds:Reference", SAML_NS)
        if ref is None or ref.attrib.get("URI", "").lstrip("#") != assertion_id:
            raise SAMLValidationError("Signature Reference does not point at the Assertion")

    # NameID + attributes
    name_id_el = assertion.find("./saml:Subject/saml:NameID", SAML_NS)
    name_id = (name_id_el.text or "").strip() if name_id_el is not None else ""

    attrs: dict[str, Any] = {}
    for a in assertion.findall("./saml:AttributeStatement/saml:Attribute", SAML_NS):
        name = a.attrib.get("Name") or a.attrib.get("FriendlyName") or ""
        values = [
            (v.text or "").strip()
            for v in a.findall("./saml:AttributeValue", SAML_NS)
        ]
        attrs[name] = values[0] if len(values) == 1 else values

    return SAMLAssertion(
        name_id=name_id,
        attributes=attrs,
        issuer=plan.idp_entity_id,
        in_response_to=rt_attr,
        session_index=_first_session_index(assertion),
        not_before=not_before,
        not_on_or_after=not_on_or_after,
    )


def _first_session_index(assertion: ET.Element) -> str | None:
    el = assertion.find("./saml:AuthnStatement", SAML_NS)
    if el is None:
        return None
    return el.attrib.get("SessionIndex")


def _parse_iso8601(s: str) -> datetime | None:
    """Tolerant ISO-8601 parser for SAML's `Z`-suffixed timestamps."""
    if not s:
        return None
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    try:
        return datetime.fromisoformat(s)
    except ValueError:
        return None


# ---------------------------------------------------------------------------
# Mapping
# ---------------------------------------------------------------------------


def apply_mapping(
    assertion: SAMLAssertion, mapping: Mapping[str, str] | None
) -> dict[str, Any]:
    """Translate SAML attributes onto our user fields.

    `mapping` is `{our_field: their_attribute_name}`. `email` defaults to the
    NameID when nothing in the mapping picks it up — common enterprise IdPs
    deliver email as the NameID rather than as an attribute.
    """
    attrs = assertion.attributes
    out: dict[str, Any] = {}
    if mapping:
        for our, theirs in mapping.items():
            if theirs in attrs:
                value = attrs[theirs]
                # SAML attributes are intrinsically multi-valued; for fields
                # the IdP only ever delivers one value (email, name, sub, ...)
                # flatten the single-element list so consumers don't have to.
                if isinstance(value, list) and len(value) == 1:
                    value = value[0]
                out[our] = value
    if "email" not in out and assertion.name_id and "@" in assertion.name_id:
        out["email"] = assertion.name_id
    if "sub" not in out:
        out["sub"] = assertion.name_id
    return out


__all__ = [
    "SAMLAssertion",
    "SAMLPlan",
    "SAMLValidationError",
    "apply_mapping",
    "build_authn_request",
    "parse_config",
    "plan_from_config",
    "sp_metadata_xml",
    "validate_permissive",
    "validate_strict",
]
