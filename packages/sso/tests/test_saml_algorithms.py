"""1:1 port of reference/packages/sso/src/saml/algorithms.test.ts.

The TS suite uses `vi.spyOn(console, "warn")`; the Python port emits warnings
via `logging.warning("[SAML Security Warning] ...")`, so warn behaviour is
asserted with pytest's `caplog` fixture.
"""

from __future__ import annotations

import logging

import pytest
from kernia.error import APIError
from kernia_sso import saml_algorithms as alg

ENCRYPTED_ASSERTION_XML = """
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">
	<saml:EncryptedAssertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
		<xenc:EncryptedData xmlns:xenc="http://www.w3.org/2001/04/xmlenc#">
			<xenc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#aes256-cbc"/>
			<ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
				<xenc:EncryptedKey>
					<xenc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p"/>
				</xenc:EncryptedKey>
			</ds:KeyInfo>
		</xenc:EncryptedData>
	</saml:EncryptedAssertion>
</samlp:Response>
"""

DEPRECATED_ENCRYPTION_XML = """
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">
	<saml:EncryptedAssertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
		<xenc:EncryptedData xmlns:xenc="http://www.w3.org/2001/04/xmlenc#">
			<xenc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#tripledes-cbc"/>
			<ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
				<xenc:EncryptedKey>
					<xenc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#rsa-1_5"/>
				</xenc:EncryptedKey>
			</ds:KeyInfo>
		</xenc:EncryptedData>
	</saml:EncryptedAssertion>
</samlp:Response>
"""

PLAIN_ASSERTION_XML = """
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">
	<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
		<saml:Subject>test</saml:Subject>
	</saml:Assertion>
</samlp:Response>
"""


def _security_warnings(caplog: pytest.LogCaptureFixture) -> list[str]:
    return [
        r.getMessage()
        for r in caplog.records
        if "SAML Security Warning" in r.getMessage()
    ]


# --------------------------------------------------------------------------- #
# validateSAMLAlgorithms - signature validation
# --------------------------------------------------------------------------- #
class TestValidateSAMLAlgorithmsSignature:
    def test_accept_secure_signature_algorithms(self) -> None:
        alg.validate_saml_algorithms(
            {"sigAlg": alg.SignatureAlgorithm.RSA_SHA256, "samlContent": PLAIN_ASSERTION_XML}
        )

    def test_warn_by_default_for_deprecated_signature(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        with caplog.at_level(logging.WARNING, logger="kernia.sso.saml"):
            alg.validate_saml_algorithms(
                {"sigAlg": alg.SignatureAlgorithm.RSA_SHA1, "samlContent": PLAIN_ASSERTION_XML}
            )
        assert _security_warnings(caplog)

    def test_reject_deprecated_signature_with_reject(self) -> None:
        with pytest.raises(APIError, match="(?i)deprecated"):
            alg.validate_saml_algorithms(
                {"sigAlg": alg.SignatureAlgorithm.RSA_SHA1, "samlContent": PLAIN_ASSERTION_XML},
                {"onDeprecated": "reject"},
            )

    def test_silently_allow_deprecated_with_allow(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        with caplog.at_level(logging.WARNING, logger="kernia.sso.saml"):
            alg.validate_saml_algorithms(
                {"sigAlg": alg.SignatureAlgorithm.RSA_SHA1, "samlContent": PLAIN_ASSERTION_XML},
                {"onDeprecated": "allow"},
            )
        assert not _security_warnings(caplog)

    def test_enforce_custom_signature_allow_list(self) -> None:
        with pytest.raises(APIError, match="(?i)not in allow-list"):
            alg.validate_saml_algorithms(
                {"sigAlg": alg.SignatureAlgorithm.RSA_SHA256, "samlContent": PLAIN_ASSERTION_XML},
                {"allowedSignatureAlgorithms": [alg.SignatureAlgorithm.RSA_SHA512]},
            )

    def test_pass_null_sig_alg_without_error(self) -> None:
        alg.validate_saml_algorithms({"sigAlg": None, "samlContent": PLAIN_ASSERTION_XML})

    def test_reject_unknown_signature_algorithms(self) -> None:
        with pytest.raises(APIError, match="(?i)not recognized"):
            alg.validate_saml_algorithms(
                {"sigAlg": "http://example.com/unknown-algo", "samlContent": PLAIN_ASSERTION_XML}
            )


# --------------------------------------------------------------------------- #
# validateSAMLAlgorithms - encryption validation
# --------------------------------------------------------------------------- #
class TestValidateSAMLAlgorithmsEncryption:
    def test_accept_secure_encryption_algorithms(self) -> None:
        alg.validate_saml_algorithms(
            {"sigAlg": alg.SignatureAlgorithm.RSA_SHA256, "samlContent": ENCRYPTED_ASSERTION_XML}
        )

    def test_warn_by_default_for_deprecated_encryption(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        with caplog.at_level(logging.WARNING, logger="kernia.sso.saml"):
            alg.validate_saml_algorithms(
                {
                    "sigAlg": alg.SignatureAlgorithm.RSA_SHA256,
                    "samlContent": DEPRECATED_ENCRYPTION_XML,
                }
            )
        assert _security_warnings(caplog)

    def test_reject_deprecated_encryption_with_reject(self) -> None:
        with pytest.raises(APIError, match="(?i)deprecated"):
            alg.validate_saml_algorithms(
                {
                    "sigAlg": alg.SignatureAlgorithm.RSA_SHA256,
                    "samlContent": DEPRECATED_ENCRYPTION_XML,
                },
                {"onDeprecated": "reject"},
            )

    def test_skip_encryption_validation_for_plain_assertions(self) -> None:
        alg.validate_saml_algorithms(
            {"sigAlg": alg.SignatureAlgorithm.RSA_SHA256, "samlContent": PLAIN_ASSERTION_XML}
        )

    def test_handle_malformed_xml_gracefully(self) -> None:
        alg.validate_saml_algorithms(
            {"sigAlg": alg.SignatureAlgorithm.RSA_SHA256, "samlContent": "not valid xml"}
        )


# --------------------------------------------------------------------------- #
# algorithm constants
# --------------------------------------------------------------------------- #
class TestAlgorithmConstants:
    def test_signature_algorithm_constants(self) -> None:
        assert (
            alg.SignatureAlgorithm.RSA_SHA256
            == "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
        )
        assert (
            alg.SignatureAlgorithm.RSA_SHA1 == "http://www.w3.org/2000/09/xmldsig#rsa-sha1"
        )

    def test_encryption_algorithm_constants(self) -> None:
        assert (
            alg.KeyEncryptionAlgorithm.RSA_OAEP
            == "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p"
        )
        assert (
            alg.DataEncryptionAlgorithm.AES_256_GCM
            == "http://www.w3.org/2009/xmlenc11#aes256-gcm"
        )


# --------------------------------------------------------------------------- #
# validateConfigAlgorithms - signature
# --------------------------------------------------------------------------- #
class TestValidateConfigAlgorithmsSignature:
    def test_accept_secure_signature_algorithms(self) -> None:
        alg.validate_config_algorithms(
            {"signatureAlgorithm": alg.SignatureAlgorithm.RSA_SHA256}
        )

    def test_warn_by_default_for_deprecated_signature(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        with caplog.at_level(logging.WARNING, logger="kernia.sso.saml"):
            alg.validate_config_algorithms(
                {"signatureAlgorithm": alg.SignatureAlgorithm.RSA_SHA1}
            )
        assert _security_warnings(caplog)

    def test_reject_deprecated_signature_with_reject(self) -> None:
        with pytest.raises(APIError, match="(?i)deprecated"):
            alg.validate_config_algorithms(
                {"signatureAlgorithm": alg.SignatureAlgorithm.RSA_SHA1},
                {"onDeprecated": "reject"},
            )

    def test_silently_allow_deprecated_with_allow(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        with caplog.at_level(logging.WARNING, logger="kernia.sso.saml"):
            alg.validate_config_algorithms(
                {"signatureAlgorithm": alg.SignatureAlgorithm.RSA_SHA1},
                {"onDeprecated": "allow"},
            )
        assert not _security_warnings(caplog)

    def test_enforce_custom_signature_allow_list(self) -> None:
        with pytest.raises(APIError, match="(?i)not in allow-list"):
            alg.validate_config_algorithms(
                {"signatureAlgorithm": alg.SignatureAlgorithm.RSA_SHA256},
                {"allowedSignatureAlgorithms": [alg.SignatureAlgorithm.RSA_SHA512]},
            )

    def test_reject_unknown_signature_algorithms(self) -> None:
        with pytest.raises(APIError, match="(?i)not recognized"):
            alg.validate_config_algorithms(
                {"signatureAlgorithm": "http://example.com/unknown-algo"}
            )

    def test_pass_undefined_signature_without_error(self) -> None:
        alg.validate_config_algorithms({})

    def test_accept_short_form_signature_names(self) -> None:
        alg.validate_config_algorithms({"signatureAlgorithm": "rsa-sha256"})

    def test_accept_digest_style_short_form_for_signature(self) -> None:
        alg.validate_config_algorithms({"signatureAlgorithm": "sha256"})

    def test_reject_typos_in_short_form_signature(self) -> None:
        with pytest.raises(APIError, match="(?i)not recognized"):
            alg.validate_config_algorithms({"signatureAlgorithm": "rsa-sha257"})

    def test_warn_for_deprecated_short_form_signature(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        with caplog.at_level(logging.WARNING, logger="kernia.sso.saml"):
            alg.validate_config_algorithms({"signatureAlgorithm": "rsa-sha1"})
        assert _security_warnings(caplog)

    def test_short_form_names_in_signature_allow_list(self) -> None:
        alg.validate_config_algorithms(
            {"signatureAlgorithm": "rsa-sha256"},
            {"allowedSignatureAlgorithms": ["rsa-sha256", "rsa-sha512"]},
        )


# --------------------------------------------------------------------------- #
# validateConfigAlgorithms - digest
# --------------------------------------------------------------------------- #
class TestValidateConfigAlgorithmsDigest:
    def test_accept_secure_digest_algorithms(self) -> None:
        alg.validate_config_algorithms({"digestAlgorithm": alg.DigestAlgorithm.SHA256})

    def test_warn_by_default_for_deprecated_digest(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        with caplog.at_level(logging.WARNING, logger="kernia.sso.saml"):
            alg.validate_config_algorithms({"digestAlgorithm": alg.DigestAlgorithm.SHA1})
        assert _security_warnings(caplog)

    def test_reject_deprecated_digest_with_reject(self) -> None:
        with pytest.raises(APIError, match="(?i)deprecated"):
            alg.validate_config_algorithms(
                {"digestAlgorithm": alg.DigestAlgorithm.SHA1},
                {"onDeprecated": "reject"},
            )

    def test_enforce_custom_digest_allow_list(self) -> None:
        with pytest.raises(APIError, match="(?i)not in allow-list"):
            alg.validate_config_algorithms(
                {"digestAlgorithm": alg.DigestAlgorithm.SHA256},
                {"allowedDigestAlgorithms": [alg.DigestAlgorithm.SHA512]},
            )

    def test_reject_unknown_digest_algorithms(self) -> None:
        with pytest.raises(APIError, match="(?i)not recognized"):
            alg.validate_config_algorithms(
                {"digestAlgorithm": "http://example.com/unknown-digest"}
            )

    def test_accept_short_form_digest_names(self) -> None:
        alg.validate_config_algorithms({"digestAlgorithm": "sha256"})

    def test_reject_typos_in_short_form_digest(self) -> None:
        with pytest.raises(APIError, match="(?i)not recognized"):
            alg.validate_config_algorithms({"digestAlgorithm": "sha257"})

    def test_warn_for_deprecated_short_form_digest(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        with caplog.at_level(logging.WARNING, logger="kernia.sso.saml"):
            alg.validate_config_algorithms({"digestAlgorithm": "sha1"})
        assert _security_warnings(caplog)

    def test_short_form_names_in_digest_allow_list(self) -> None:
        alg.validate_config_algorithms(
            {"digestAlgorithm": "sha256"},
            {"allowedDigestAlgorithms": ["sha256", "sha512"]},
        )


# --------------------------------------------------------------------------- #
# validateConfigAlgorithms - combined
# --------------------------------------------------------------------------- #
class TestValidateConfigAlgorithmsCombined:
    def test_validate_both_signature_and_digest(self) -> None:
        alg.validate_config_algorithms(
            {
                "signatureAlgorithm": alg.SignatureAlgorithm.RSA_SHA256,
                "digestAlgorithm": alg.DigestAlgorithm.SHA256,
            }
        )

    def test_reject_if_signature_deprecated_even_if_digest_secure(self) -> None:
        with pytest.raises(APIError, match="(?i)deprecated"):
            alg.validate_config_algorithms(
                {
                    "signatureAlgorithm": alg.SignatureAlgorithm.RSA_SHA1,
                    "digestAlgorithm": alg.DigestAlgorithm.SHA256,
                },
                {"onDeprecated": "reject"},
            )

    def test_reject_if_digest_deprecated_even_if_signature_secure(self) -> None:
        with pytest.raises(APIError, match="(?i)deprecated"):
            alg.validate_config_algorithms(
                {
                    "signatureAlgorithm": alg.SignatureAlgorithm.RSA_SHA256,
                    "digestAlgorithm": alg.DigestAlgorithm.SHA1,
                },
                {"onDeprecated": "reject"},
            )
