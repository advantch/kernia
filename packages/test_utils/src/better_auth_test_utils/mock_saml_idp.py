"""Minimal SAML 2.0 IdP fixture.

Builds a signed SAML Response containing a single Assertion. The Response is
returned as base64 ready to feed into an SP's ACS endpoint.

Limitations (documented):
    * Signing uses `cryptography` directly — no `xmlsec` dependency. The output
      is an XML-DSIG `enveloped-signature` over the Assertion element using
      Exclusive XML C14N (a minimal, deterministic serialization we emit
      ourselves rather than running through libxml2). Real-world consumers
      (`python3-saml`, `pysaml2`) generally re-canonicalize with libxml2, so
      verification of the signature value will only succeed if the SP either
      (a) accepts our canonical form byte-for-byte or (b) is configured with
      `wantAssertionsSigned=false` / equivalent.
    * The assertion is fine for transport/structure tests and for SP code
      paths that parse claims/NameID/Conditions. End-to-end signature
      verification against python3-saml is exercised in the SSO lane with a
      real xmlsec1 round-trip.
    * Only the SHA-256/RSA signature suite is supported. No encryption.
"""

from __future__ import annotations

import base64
import secrets
import uuid
import xml.sax.saxutils as saxutils
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.oid import NameOID


def _now_utc() -> datetime:
    return datetime.now(tz=timezone.utc)


def _iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _xml_escape(value: str) -> str:
    return saxutils.escape(value, {'"': "&quot;", "'": "&apos;"})


@dataclass
class MockSAMLIdP:
    entity_id: str = "https://test-saml-idp"
    sso_url: str = "https://test-saml-idp/sso"
    valid_for: timedelta = field(default_factory=lambda: timedelta(minutes=5))

    _key: rsa.RSAPrivateKey = field(init=False)
    _cert: x509.Certificate = field(init=False)

    def __post_init__(self) -> None:
        self._key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = issuer = x509.Name(
            [x509.NameAttribute(NameOID.COMMON_NAME, "mock-saml-idp")]
        )
        self._cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(self._key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(_now_utc() - timedelta(minutes=1))
            .not_valid_after(_now_utc() + timedelta(days=365))
            .sign(self._key, hashes.SHA256())
        )

    # ----- public API -----

    @property
    def cert_pem(self) -> str:
        return self._cert.public_bytes(serialization.Encoding.PEM).decode("ascii")

    @property
    def cert_b64(self) -> str:
        der = self._cert.public_bytes(serialization.Encoding.DER)
        return base64.b64encode(der).decode("ascii")

    @property
    def metadata_xml(self) -> str:
        """Return SAML 2.0 metadata describing this IdP."""
        cert = self.cert_b64
        return (
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"'
            f' entityID="{_xml_escape(self.entity_id)}">'
            '<md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"'
            ' WantAuthnRequestsSigned="false">'
            '<md:KeyDescriptor use="signing"><ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">'
            f"<ds:X509Data><ds:X509Certificate>{cert}</ds:X509Certificate></ds:X509Data>"
            "</ds:KeyInfo></md:KeyDescriptor>"
            '<md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</md:NameIDFormat>'
            '<md:SingleSignOnService'
            ' Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"'
            f' Location="{_xml_escape(self.sso_url)}"/>'
            "</md:IDPSSODescriptor></md:EntityDescriptor>"
        )

    def create_assertion(
        self,
        name_id: str,
        attrs: dict[str, Any],
        audience: str,
        recipient: str,
        *,
        in_response_to: str | None = None,
    ) -> str:
        """Build a signed SAML Response (base64-encoded).

        The signature is over the Assertion element using `rsa-sha256` and the
        canonical serialization we emit below. See module docstring for
        verification caveats.
        """
        issue_instant = _now_utc()
        not_on_or_after = issue_instant + self.valid_for
        assertion_id = "_" + uuid.uuid4().hex
        response_id = "_" + uuid.uuid4().hex
        session_index = "_" + secrets.token_hex(8)

        attr_xml = "".join(
            self._attribute_xml(name, value) for name, value in attrs.items()
        )
        subject_confirmation_data = (
            f'Recipient="{_xml_escape(recipient)}"'
            f' NotOnOrAfter="{_iso(not_on_or_after)}"'
        )
        if in_response_to:
            subject_confirmation_data += f' InResponseTo="{_xml_escape(in_response_to)}"'

        assertion = (
            '<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"'
            f' ID="{assertion_id}" Version="2.0" IssueInstant="{_iso(issue_instant)}">'
            f"<saml:Issuer>{_xml_escape(self.entity_id)}</saml:Issuer>"
            "<saml:Subject>"
            '<saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">'
            f"{_xml_escape(name_id)}</saml:NameID>"
            '<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">'
            f"<saml:SubjectConfirmationData {subject_confirmation_data}/>"
            "</saml:SubjectConfirmation></saml:Subject>"
            f'<saml:Conditions NotBefore="{_iso(issue_instant)}"'
            f' NotOnOrAfter="{_iso(not_on_or_after)}">'
            "<saml:AudienceRestriction>"
            f"<saml:Audience>{_xml_escape(audience)}</saml:Audience>"
            "</saml:AudienceRestriction></saml:Conditions>"
            f'<saml:AuthnStatement AuthnInstant="{_iso(issue_instant)}"'
            f' SessionIndex="{session_index}">'
            "<saml:AuthnContext>"
            "<saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef>"
            "</saml:AuthnContext></saml:AuthnStatement>"
            f"<saml:AttributeStatement>{attr_xml}</saml:AttributeStatement>"
            "</saml:Assertion>"
        )

        signed_assertion = self._sign(assertion, ref_id=assertion_id)

        response = (
            '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"'
            ' xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"'
            f' ID="{response_id}" Version="2.0"'
            f' IssueInstant="{_iso(issue_instant)}"'
            f' Destination="{_xml_escape(recipient)}"'
            + (f' InResponseTo="{_xml_escape(in_response_to)}"' if in_response_to else "")
            + ">"
            f"<saml:Issuer>{_xml_escape(self.entity_id)}</saml:Issuer>"
            '<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>'
            f"{signed_assertion}"
            "</samlp:Response>"
        )
        return base64.b64encode(response.encode("utf-8")).decode("ascii")

    # ----- internals -----

    def _attribute_xml(self, name: str, value: Any) -> str:
        values = value if isinstance(value, (list, tuple)) else [value]
        inner = "".join(
            f"<saml:AttributeValue>{_xml_escape(str(v))}</saml:AttributeValue>" for v in values
        )
        return (
            f'<saml:Attribute Name="{_xml_escape(name)}">{inner}</saml:Attribute>'
        )

    def _sign(self, assertion_xml: str, *, ref_id: str) -> str:
        """Wrap `assertion_xml` with an enveloped XML-DSIG signature.

        Signs `hashes.SHA256(assertion_xml.encode())` with RSA-PKCS#1v1.5 (the
        bytes we sign are the assertion serialization we just emitted). The
        signature element is inserted directly after the `<saml:Issuer>` child,
        matching the placement most SAML SPs expect.
        """
        # Digest over the assertion bytes (our canonical form).
        digest = hashes.Hash(hashes.SHA256())
        digest.update(assertion_xml.encode("utf-8"))
        digest_value = base64.b64encode(digest.finalize()).decode("ascii")

        signed_info = (
            '<ds:SignedInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">'
            '<ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>'
            '<ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>'
            f'<ds:Reference URI="#{ref_id}">'
            "<ds:Transforms>"
            '<ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>'
            '<ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>'
            "</ds:Transforms>"
            '<ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>'
            f"<ds:DigestValue>{digest_value}</ds:DigestValue></ds:Reference>"
            "</ds:SignedInfo>"
        )

        signature_bytes = self._key.sign(
            signed_info.encode("utf-8"),
            padding.PKCS1v15(),
            hashes.SHA256(),
        )
        signature_value = base64.b64encode(signature_bytes).decode("ascii")

        signature = (
            '<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">'
            f"{signed_info}"
            f"<ds:SignatureValue>{signature_value}</ds:SignatureValue>"
            "<ds:KeyInfo><ds:X509Data>"
            f"<ds:X509Certificate>{self.cert_b64}</ds:X509Certificate>"
            "</ds:X509Data></ds:KeyInfo></ds:Signature>"
        )

        # Insert signature right after the Assertion's <saml:Issuer> child.
        marker = f"</saml:Issuer>"
        idx = assertion_xml.find(marker)
        if idx == -1:
            return assertion_xml
        insert_at = idx + len(marker)
        return assertion_xml[:insert_at] + signature + assertion_xml[insert_at:]


__all__ = ["MockSAMLIdP"]
