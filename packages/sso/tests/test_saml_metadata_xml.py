"""Unit tests for SP metadata generation.

Verifies the generated XML is well-formed and contains the standard SAML 2.0
metadata elements an IdP expects.
"""

from __future__ import annotations

from xml.etree import ElementTree as ET

import pytest

from better_auth_sso.saml import SAMLPlan, sp_metadata_xml


@pytest.fixture
def plan() -> SAMLPlan:
    # The IdP cert is required even though we're only emitting SP metadata —
    # python3-saml's settings validator wants a non-empty IdP block.
    return SAMLPlan(
        sp_entity_id="https://app.example/sso/saml/metadata/p-1",
        acs_url="https://app.example/sso/saml/acs/p-1",
        slo_url="https://app.example/sso/saml/slo/p-1",
        idp_entity_id="https://idp.example",
        idp_sso_url="https://idp.example/sso",
        idp_slo_url="https://idp.example/slo",
        idp_cert=(
            "MIIBIDANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1234567890ABCDEFGH"
        ),
    )


async def test_metadata_is_wellformed_xml(plan: SAMLPlan) -> None:
    xml = await sp_metadata_xml(plan)
    root = ET.fromstring(xml)
    # Top-level is an EntityDescriptor in the SAML metadata namespace.
    assert root.tag.endswith("EntityDescriptor")
    assert root.attrib.get("entityID") == plan.sp_entity_id


async def test_metadata_advertises_acs_and_slo(plan: SAMLPlan) -> None:
    xml = await sp_metadata_xml(plan)
    # ACS URL appears verbatim.
    assert plan.acs_url in xml
    # SLO URL appears verbatim.
    assert plan.slo_url in xml


async def test_metadata_contains_sp_descriptor(plan: SAMLPlan) -> None:
    xml = await sp_metadata_xml(plan)
    root = ET.fromstring(xml)
    ns = "urn:oasis:names:tc:SAML:2.0:metadata"
    sp_descriptor = root.find(f"{{{ns}}}SPSSODescriptor")
    assert sp_descriptor is not None, "no SPSSODescriptor in metadata"
    # NameIDFormat is included.
    name_id_fmt = sp_descriptor.find(f"{{{ns}}}NameIDFormat")
    assert name_id_fmt is not None and "emailAddress" in (name_id_fmt.text or "")


async def test_metadata_contains_assertion_consumer_binding(plan: SAMLPlan) -> None:
    xml = await sp_metadata_xml(plan)
    root = ET.fromstring(xml)
    ns = "urn:oasis:names:tc:SAML:2.0:metadata"
    acs = root.find(f".//{{{ns}}}AssertionConsumerService")
    assert acs is not None
    assert acs.attrib.get("Location") == plan.acs_url
    assert "HTTP-POST" in acs.attrib.get("Binding", "")
