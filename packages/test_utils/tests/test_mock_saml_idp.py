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


def test_signature_verifies_over_c14n_signed_info() -> None:
    """SignatureValue is a valid RSA-SHA256 signature over the c14n form of the
    SignedInfo element — this is the strict XML-DSIG contract that python3-saml
    and xmlsec rebuild during verification."""
    from lxml import etree

    idp = MockSAMLIdP()
    encoded = idp.create_assertion(
        name_id="u",
        attrs={"email": "u@x"},
        audience="sp",
        recipient="https://sp/acs",
    )
    xml_bytes = base64.b64decode(encoded)
    root = etree.fromstring(xml_bytes)

    signed_info = root.find(".//ds:SignedInfo", NS)
    sig_value_el = root.find(".//ds:SignatureValue", NS)
    assert signed_info is not None and sig_value_el is not None
    signature = base64.b64decode(sig_value_el.text or "")

    signed_info_c14n = etree.tostring(
        signed_info, method="c14n", exclusive=True, with_comments=False
    )

    pub = idp._key.public_key()  # noqa: SLF001 — test-internal access
    pub.verify(
        signature,
        signed_info_c14n,
        padding.PKCS1v15(),
        hashes.SHA256(),
    )


def test_reference_digest_matches_c14n_of_assertion_minus_signature() -> None:
    """The DigestValue inside SignedInfo == SHA-256(c14n(assertion - Signature)),
    matching the Reference's enveloped-signature + exc-c14n Transforms chain.
    This is the second half of the XML-DSIG round-trip that python3-saml runs.
    """
    from lxml import etree
    from cryptography.hazmat.primitives import hashes as _h

    idp = MockSAMLIdP()
    encoded = idp.create_assertion(
        name_id="u",
        attrs={"email": "u@x"},
        audience="sp",
        recipient="https://sp/acs",
    )
    xml_bytes = base64.b64decode(encoded)
    root = etree.fromstring(xml_bytes)

    assertion = root.find("saml:Assertion", NS)
    assert assertion is not None

    # Apply the Reference's first Transform (enveloped-signature): drop the
    # Signature child from a copy.
    import copy

    assertion_copy = copy.deepcopy(assertion)
    sig_in_copy = assertion_copy.find("ds:Signature", NS)
    if sig_in_copy is not None:
        assertion_copy.remove(sig_in_copy)

    # Apply the Reference's second Transform (exc-c14n).
    assertion_c14n = etree.tostring(
        assertion_copy, method="c14n", exclusive=True, with_comments=False
    )
    d = _h.Hash(_h.SHA256())
    d.update(assertion_c14n)
    computed_digest = base64.b64encode(d.finalize()).decode("ascii")

    declared_digest = root.find(".//ds:DigestValue", NS).text  # type: ignore[union-attr]
    assert declared_digest == computed_digest
