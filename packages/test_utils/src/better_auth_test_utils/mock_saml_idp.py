"""Minimal SAML 2.0 IdP fixture with strict XML-DSIG signing.

Builds a signed SAML Response containing a single Assertion. The Response is
returned as base64 ready to feed into an SP's ACS endpoint.

Signing uses `lxml`'s built-in Exclusive XML Canonicalization (libxml2-backed)
so the signature digest and SignatureValue are computed over the same canonical
bytes a strict SP (e.g. `python3-saml`, `pysaml2`, `xmlsec`) computes during
verification. Only RSA-SHA256 is supported. No encryption.

The previous version of this fixture signed over our own serialization, which
strict XML-DSIG verifiers would reject. Strict verification now works as long
as the SP is configured with the IdP's cert.
"""

from __future__ import annotations

import base64
import secrets
import uuid
import xml.sax.saxutils as saxutils
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.oid import NameOID


def _now_utc() -> datetime:
    return datetime.now(tz=UTC)


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
        values = value if isinstance(value, list | tuple) else [value]
        inner = "".join(
            f"<saml:AttributeValue>{_xml_escape(str(v))}</saml:AttributeValue>" for v in values
        )
        return (
            f'<saml:Attribute Name="{_xml_escape(name)}">{inner}</saml:Attribute>'
        )

    def _sign(self, assertion_xml: str, *, ref_id: str) -> str:
        """Wrap `assertion_xml` with a strict XML-DSIG enveloped signature.

        Conforms to xmldsig-core §4 + xml-exc-c14n. Uses lxml for canonicalization
        so the bytes we sign exactly match the bytes a verifier (python3-saml,
        xmlsec) will reconstruct.

        Steps:
          1. Parse the assertion as XML.
          2. Compute Reference digest:
                c14n(assertion with the (not-yet-inserted) Signature element
                     subtracted by the enveloped-signature transform)
             Since there is no Signature inside yet, the enveloped-signature
             transform is a no-op; we just c14n the assertion as-is.
          3. Build SignedInfo with that digest.
          4. Compute SignatureValue = RSA-SHA256(c14n(SignedInfo)).
          5. Insert the assembled Signature element immediately after the
             Assertion's <saml:Issuer> child (the standard placement).
        """
        from lxml import etree

        ns = {
            "saml": "urn:oasis:names:tc:SAML:2.0:assertion",
            "ds": "http://www.w3.org/2000/09/xmldsig#",
        }

        # Parse the (unsigned) assertion. The c14n method we use here is the
        # one the Reference Transforms also specify (exclusive c14n).
        assertion_elem = etree.fromstring(assertion_xml.encode("utf-8"))
        assertion_c14n = etree.tostring(
            assertion_elem,
            method="c14n",
            exclusive=True,
            with_comments=False,
        )
        digest = hashes.Hash(hashes.SHA256())
        digest.update(assertion_c14n)
        digest_value = base64.b64encode(digest.finalize()).decode("ascii")

        signed_info_xml = (
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

        # Canonicalize SignedInfo before signing — strict verifiers rebuild
        # exactly these bytes from the parsed SignedInfo node.
        signed_info_elem = etree.fromstring(signed_info_xml.encode("utf-8"))
        signed_info_c14n = etree.tostring(
            signed_info_elem,
            method="c14n",
            exclusive=True,
            with_comments=False,
        )
        signature_bytes = self._key.sign(
            signed_info_c14n,
            padding.PKCS1v15(),
            hashes.SHA256(),
        )
        signature_value = base64.b64encode(signature_bytes).decode("ascii")

        signature_xml = (
            '<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">'
            f"{signed_info_xml}"
            f"<ds:SignatureValue>{signature_value}</ds:SignatureValue>"
            "<ds:KeyInfo><ds:X509Data>"
            f"<ds:X509Certificate>{self.cert_b64}</ds:X509Certificate>"
            "</ds:X509Data></ds:KeyInfo></ds:Signature>"
        )

        # Insert <ds:Signature> right after <saml:Issuer> (the standard slot).
        issuer = assertion_elem.find("saml:Issuer", namespaces=ns)
        if issuer is None:
            return assertion_xml
        signature_elem = etree.fromstring(signature_xml.encode("utf-8"))
        # Place the signature element as the next sibling after Issuer.
        issuer.addnext(signature_elem)

        # Serialize the now-signed assertion. We deliberately serialize the
        # in-memory tree (lxml decides on the literal byte ordering); the
        # signature byte-positions are still valid because c14n is canonical.
        return etree.tostring(assertion_elem, encoding="unicode")


__all__ = ["MockSAMLIdP"]
