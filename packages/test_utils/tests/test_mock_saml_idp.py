"""MockSAMLIdP: structural / signature sanity checks.

Full python3-saml SP-side verification is exercised in the SSO lane.
"""

from __future__ import annotations

import base64
import xml.etree.ElementTree as ET

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

from better_auth_test_utils import MockSAMLIdP

NS = {
    "samlp": "urn:oasis:names:tc:SAML:2.0:protocol",
    "saml": "urn:oasis:names:tc:SAML:2.0:assertion",
    "md": "urn:oasis:names:tc:SAML:2.0:metadata",
    "ds": "http://www.w3.org/2000/09/xmldsig#",
}


def test_metadata_is_valid_xml_with_cert() -> None:
    idp = MockSAMLIdP()
    root = ET.fromstring(idp.metadata_xml)
    assert root.tag.endswith("EntityDescriptor")
    cert = root.find(".//ds:X509Certificate", NS)
    assert cert is not None and cert.text
    # Must be valid base64 DER.
    base64.b64decode(cert.text)


def test_assertion_is_well_formed_and_carries_claims() -> None:
    idp = MockSAMLIdP(entity_id="https://idp", sso_url="https://idp/sso")
    encoded = idp.create_assertion(
        name_id="user@x",
        attrs={"email": "user@x", "groups": ["admin", "users"]},
        audience="sp-1",
        recipient="https://sp/acs",
    )
    xml_bytes = base64.b64decode(encoded)
    root = ET.fromstring(xml_bytes)
    assert root.tag == f"{{{NS['samlp']}}}Response"
    assertion = root.find("saml:Assertion", NS)
    assert assertion is not None

    name_id = assertion.find("saml:Subject/saml:NameID", NS)
    assert name_id is not None and name_id.text == "user@x"

    audience = assertion.find(
        "saml:Conditions/saml:AudienceRestriction/saml:Audience", NS
    )
    assert audience is not None and audience.text == "sp-1"

    attrs = assertion.findall("saml:AttributeStatement/saml:Attribute", NS)
    by_name = {a.attrib["Name"]: a for a in attrs}
    assert set(by_name) == {"email", "groups"}
    group_values = [
        v.text for v in by_name["groups"].findall("saml:AttributeValue", NS)
    ]
    assert group_values == ["admin", "users"]


def test_signature_verifies_over_signed_info() -> None:
    """The SignatureValue is a valid RSA-SHA256 signature over the SignedInfo
    element bytes the IdP emitted. This is a structural check, not a full
    XML-DSIG canonicalization round-trip (see module docstring)."""
    idp = MockSAMLIdP()
    encoded = idp.create_assertion(
        name_id="u",
        attrs={"email": "u@x"},
        audience="sp",
        recipient="https://sp/acs",
    )
    xml_text = base64.b64decode(encoded).decode("utf-8")

    # Locate SignedInfo and SignatureValue substrings as emitted.
    si_start = xml_text.index("<ds:SignedInfo")
    si_end = xml_text.index("</ds:SignedInfo>") + len("</ds:SignedInfo>")
    signed_info_bytes = xml_text[si_start:si_end].encode("utf-8")

    sv_start = xml_text.index("<ds:SignatureValue>") + len("<ds:SignatureValue>")
    sv_end = xml_text.index("</ds:SignatureValue>")
    sig_b64 = xml_text[sv_start:sv_end]
    signature = base64.b64decode(sig_b64)

    pub = idp._key.public_key()  # noqa: SLF001 — test-internal access
    pub.verify(
        signature,
        signed_info_bytes,
        padding.PKCS1v15(),
        hashes.SHA256(),
    )
