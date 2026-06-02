"""1:1 port of reference/packages/sso/src/saml/assertions.test.ts."""

from __future__ import annotations

import base64
import re

import pytest
from kernia.error import APIError
from kernia_sso.saml_assertions import count_assertions, validate_single_assertion


def _encode(xml: str) -> str:
    return base64.b64encode(xml.encode("utf-8")).decode("ascii")


# --------------------------------------------------------------------------- #
# validateSingleAssertion - valid responses (exactly 1 assertion)
# --------------------------------------------------------------------------- #
class TestValidResponses:
    def test_accept_response_with_single_assertion(self) -> None:
        xml = """
			<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
				<saml:Assertion ID="123">
					<saml:Subject><saml:NameID>user@example.com</saml:NameID></saml:Subject>
				</saml:Assertion>
			</samlp:Response>
		"""
        validate_single_assertion(_encode(xml))

    def test_accept_response_with_single_encrypted_assertion(self) -> None:
        xml = """
			<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
				<saml:EncryptedAssertion>
					<xenc:EncryptedData>...</xenc:EncryptedData>
				</saml:EncryptedAssertion>
			</samlp:Response>
		"""
        validate_single_assertion(_encode(xml))


# --------------------------------------------------------------------------- #
# base64 whitespace handling
# https://github.com/better-auth/better-auth/issues/8921
# --------------------------------------------------------------------------- #
class TestBase64WhitespaceHandling:
    def test_accept_base64_with_embedded_whitespace(self) -> None:
        xml = """
			<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
				<saml:Assertion ID="123">
					<saml:Subject><saml:NameID>user@example.com</saml:NameID></saml:Subject>
				</saml:Assertion>
			</samlp:Response>
		"""
        b64 = _encode(xml)

        wrapped_lf = re.sub(r"(.{76})", r"\1\n", b64)
        wrapped_crlf = re.sub(r"(.{76})", r"\1\r\n", b64)
        wrapped_spaces_and_tabs = re.sub(r"(.{20})", r"\1 \t ", b64)

        assert "\n" in wrapped_lf
        assert "\r\n" in wrapped_crlf
        assert " \t " in wrapped_spaces_and_tabs

        validate_single_assertion(wrapped_lf)
        validate_single_assertion(wrapped_crlf)
        validate_single_assertion(wrapped_spaces_and_tabs)


# --------------------------------------------------------------------------- #
# no assertions
# --------------------------------------------------------------------------- #
class TestNoAssertions:
    def test_reject_response_with_no_assertions(self) -> None:
        xml = """
			<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">
				<samlp:Status>
					<samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
				</samlp:Status>
			</samlp:Response>
		"""
        with pytest.raises(APIError, match="SAML response contains no assertions"):
            validate_single_assertion(_encode(xml))


# --------------------------------------------------------------------------- #
# multiple assertions
# --------------------------------------------------------------------------- #
class TestMultipleAssertions:
    def test_reject_multiple_unencrypted_assertions(self) -> None:
        xml = """
			<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
				<saml:Assertion ID="assertion1">
					<saml:Subject><saml:NameID>user@example.com</saml:NameID></saml:Subject>
				</saml:Assertion>
				<saml:Assertion ID="assertion2">
					<saml:Subject><saml:NameID>attacker@evil.com</saml:NameID></saml:Subject>
				</saml:Assertion>
			</samlp:Response>
		"""
        with pytest.raises(
            APIError, match="SAML response contains 2 assertions, expected exactly 1"
        ):
            validate_single_assertion(_encode(xml))

    def test_reject_multiple_encrypted_assertions(self) -> None:
        xml = """
			<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
				<saml:EncryptedAssertion>
					<xenc:EncryptedData>...</xenc:EncryptedData>
				</saml:EncryptedAssertion>
				<saml:EncryptedAssertion>
					<xenc:EncryptedData>...</xenc:EncryptedData>
				</saml:EncryptedAssertion>
			</samlp:Response>
		"""
        with pytest.raises(
            APIError, match="SAML response contains 2 assertions, expected exactly 1"
        ):
            validate_single_assertion(_encode(xml))

    def test_reject_mixed_assertion_types(self) -> None:
        xml = """
			<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
				<saml:Assertion ID="plain-assertion">
					<saml:Subject><saml:NameID>user@example.com</saml:NameID></saml:Subject>
				</saml:Assertion>
				<saml:EncryptedAssertion>
					<xenc:EncryptedData>...</xenc:EncryptedData>
				</saml:EncryptedAssertion>
			</samlp:Response>
		"""
        with pytest.raises(
            APIError, match="SAML response contains 2 assertions, expected exactly 1"
        ):
            validate_single_assertion(_encode(xml))


# --------------------------------------------------------------------------- #
# XSW attack patterns
# --------------------------------------------------------------------------- #
class TestXSWAttackPatterns:
    def test_reject_assertion_injected_in_extensions(self) -> None:
        xml = """
			<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
				<samlp:Extensions>
					<saml:Assertion ID="injected-assertion">
						<saml:Subject><saml:NameID>attacker@evil.com</saml:NameID></saml:Subject>
					</saml:Assertion>
				</samlp:Extensions>
				<saml:Assertion ID="legitimate-assertion">
					<saml:Subject><saml:NameID>user@example.com</saml:NameID></saml:Subject>
				</saml:Assertion>
			</samlp:Response>
		"""
        with pytest.raises(
            APIError, match="SAML response contains 2 assertions, expected exactly 1"
        ):
            validate_single_assertion(_encode(xml))

    def test_reject_assertion_wrapped_in_arbitrary_element(self) -> None:
        xml = """
			<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
				<Wrapper>
					<saml:Assertion ID="wrapped-assertion">
						<saml:Subject><saml:NameID>attacker@evil.com</saml:NameID></saml:Subject>
					</saml:Assertion>
				</Wrapper>
				<saml:Assertion ID="legitimate-assertion">
					<saml:Subject><saml:NameID>user@example.com</saml:NameID></saml:Subject>
				</saml:Assertion>
			</samlp:Response>
		"""
        with pytest.raises(
            APIError, match="SAML response contains 2 assertions, expected exactly 1"
        ):
            validate_single_assertion(_encode(xml))

    def test_reject_deeply_nested_injected_assertion(self) -> None:
        xml = """
			<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
				<Level1>
					<Level2>
						<Level3>
							<saml:Assertion ID="deep-injected">
								<saml:Subject><saml:NameID>attacker@evil.com</saml:NameID></saml:Subject>
							</saml:Assertion>
						</Level3>
					</Level2>
				</Level1>
				<saml:Assertion ID="legitimate-assertion">
					<saml:Subject><saml:NameID>user@example.com</saml:NameID></saml:Subject>
				</saml:Assertion>
			</samlp:Response>
		"""
        with pytest.raises(
            APIError, match="SAML response contains 2 assertions, expected exactly 1"
        ):
            validate_single_assertion(_encode(xml))


# --------------------------------------------------------------------------- #
# namespace handling
# --------------------------------------------------------------------------- #
class TestNamespaceHandling:
    def test_assertion_without_namespace_prefix(self) -> None:
        xml = """
			<Response>
				<Assertion ID="123">
					<Subject><NameID>user@example.com</NameID></Subject>
				</Assertion>
			</Response>
		"""
        validate_single_assertion(_encode(xml))

    def test_assertion_with_saml2_prefix(self) -> None:
        xml = """
			<saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">
				<saml2:Assertion ID="123">
					<saml2:Subject><saml2:NameID>user@example.com</saml2:NameID></saml2:Subject>
				</saml2:Assertion>
			</saml2p:Response>
		"""
        validate_single_assertion(_encode(xml))

    def test_assertion_with_custom_prefix(self) -> None:
        xml = """
			<custom:Response xmlns:custom="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:myprefix="urn:oasis:names:tc:SAML:2.0:assertion">
				<myprefix:Assertion ID="123">
					<myprefix:Subject><myprefix:NameID>user@example.com</myprefix:NameID></myprefix:Subject>
				</myprefix:Assertion>
			</custom:Response>
		"""
        validate_single_assertion(_encode(xml))


# --------------------------------------------------------------------------- #
# countAssertions
# --------------------------------------------------------------------------- #
class TestCountAssertions:
    def test_separate_counts_for_assertions_and_encrypted(self) -> None:
        xml = """
			<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
				<saml:Assertion ID="plain">
					<saml:Subject><saml:NameID>user@example.com</saml:NameID></saml:Subject>
				</saml:Assertion>
				<saml:EncryptedAssertion>
					<xenc:EncryptedData>...</xenc:EncryptedData>
				</saml:EncryptedAssertion>
			</samlp:Response>
		"""
        counts = count_assertions(xml)
        assert counts.assertions == 1
        assert counts.encrypted_assertions == 1
        assert counts.total == 2

    def test_does_not_count_assertion_consumer_service(self) -> None:
        xml = """
			<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata">
				<md:SPSSODescriptor>
					<md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="http://example.com/acs"/>
				</md:SPSSODescriptor>
			</md:EntityDescriptor>
		"""
        counts = count_assertions(xml)
        assert counts.assertions == 0
        assert counts.total == 0


# --------------------------------------------------------------------------- #
# error handling
# --------------------------------------------------------------------------- #
class TestErrorHandling:
    def test_reject_invalid_base64_input(self) -> None:
        with pytest.raises(APIError, match="Invalid base64-encoded SAML response"):
            validate_single_assertion("not-valid-base64!!!")

    def test_reject_non_xml_content(self) -> None:
        not_xml = _encode("this is not xml at all")
        with pytest.raises(APIError, match="Invalid base64-encoded SAML response"):
            validate_single_assertion(not_xml)
