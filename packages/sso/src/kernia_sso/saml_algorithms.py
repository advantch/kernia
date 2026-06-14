"""SAML signature / digest / encryption algorithm validation.

1:1 port of `reference/packages/sso/src/saml/algorithms.ts`.

Deprecated algorithms (SHA-1, RSA1_5, 3DES) can be rejected, warned about, or
silently allowed via :class:`AlgorithmValidationOptions.on_deprecated`. Short-form
algorithm names (``"rsa-sha256"``, ``"sha256"``) are normalized to their full
XML-DSIG URIs before comparison.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

from kernia.error import APIError

from kernia_sso.saml_parser import find_node, parse_xml

logger = logging.getLogger("kernia.sso.saml")


class SignatureAlgorithm:
    RSA_SHA1 = "http://www.w3.org/2000/09/xmldsig#rsa-sha1"
    RSA_SHA256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
    RSA_SHA384 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384"
    RSA_SHA512 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512"
    ECDSA_SHA256 = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256"
    ECDSA_SHA384 = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384"
    ECDSA_SHA512 = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512"


class DigestAlgorithm:
    SHA1 = "http://www.w3.org/2000/09/xmldsig#sha1"
    SHA256 = "http://www.w3.org/2001/04/xmlenc#sha256"
    SHA384 = "http://www.w3.org/2001/04/xmldsig-more#sha384"
    SHA512 = "http://www.w3.org/2001/04/xmlenc#sha512"


class KeyEncryptionAlgorithm:
    RSA_1_5 = "http://www.w3.org/2001/04/xmlenc#rsa-1_5"
    RSA_OAEP = "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p"
    RSA_OAEP_SHA256 = "http://www.w3.org/2009/xmlenc11#rsa-oaep"


class DataEncryptionAlgorithm:
    TRIPLEDES_CBC = "http://www.w3.org/2001/04/xmlenc#tripledes-cbc"
    AES_128_CBC = "http://www.w3.org/2001/04/xmlenc#aes128-cbc"
    AES_192_CBC = "http://www.w3.org/2001/04/xmlenc#aes192-cbc"
    AES_256_CBC = "http://www.w3.org/2001/04/xmlenc#aes256-cbc"
    AES_128_GCM = "http://www.w3.org/2009/xmlenc11#aes128-gcm"
    AES_192_GCM = "http://www.w3.org/2009/xmlenc11#aes192-gcm"
    AES_256_GCM = "http://www.w3.org/2009/xmlenc11#aes256-gcm"


_DEPRECATED_SIGNATURE_ALGORITHMS = (SignatureAlgorithm.RSA_SHA1,)
_DEPRECATED_KEY_ENCRYPTION_ALGORITHMS = (KeyEncryptionAlgorithm.RSA_1_5,)
_DEPRECATED_DATA_ENCRYPTION_ALGORITHMS = (DataEncryptionAlgorithm.TRIPLEDES_CBC,)
_DEPRECATED_DIGEST_ALGORITHMS = (DigestAlgorithm.SHA1,)

_SECURE_SIGNATURE_ALGORITHMS = (
    SignatureAlgorithm.RSA_SHA256,
    SignatureAlgorithm.RSA_SHA384,
    SignatureAlgorithm.RSA_SHA512,
    SignatureAlgorithm.ECDSA_SHA256,
    SignatureAlgorithm.ECDSA_SHA384,
    SignatureAlgorithm.ECDSA_SHA512,
)

_SECURE_DIGEST_ALGORITHMS = (
    DigestAlgorithm.SHA256,
    DigestAlgorithm.SHA384,
    DigestAlgorithm.SHA512,
)

_SHORT_FORM_SIGNATURE_TO_URI = {
    "sha1": SignatureAlgorithm.RSA_SHA1,
    "sha256": SignatureAlgorithm.RSA_SHA256,
    "sha384": SignatureAlgorithm.RSA_SHA384,
    "sha512": SignatureAlgorithm.RSA_SHA512,
    "rsa-sha1": SignatureAlgorithm.RSA_SHA1,
    "rsa-sha256": SignatureAlgorithm.RSA_SHA256,
    "rsa-sha384": SignatureAlgorithm.RSA_SHA384,
    "rsa-sha512": SignatureAlgorithm.RSA_SHA512,
    "ecdsa-sha256": SignatureAlgorithm.ECDSA_SHA256,
    "ecdsa-sha384": SignatureAlgorithm.ECDSA_SHA384,
    "ecdsa-sha512": SignatureAlgorithm.ECDSA_SHA512,
}

_SHORT_FORM_DIGEST_TO_URI = {
    "sha1": DigestAlgorithm.SHA1,
    "sha256": DigestAlgorithm.SHA256,
    "sha384": DigestAlgorithm.SHA384,
    "sha512": DigestAlgorithm.SHA512,
}


def _normalize_signature_algorithm(alg: str) -> str:
    return _SHORT_FORM_SIGNATURE_TO_URI.get(alg.lower(), alg)


def _normalize_digest_algorithm(alg: str) -> str:
    return _SHORT_FORM_DIGEST_TO_URI.get(alg.lower(), alg)


@dataclass(slots=True)
class AlgorithmValidationOptions:
    on_deprecated: str = "warn"  # "reject" | "warn" | "allow"
    allowed_signature_algorithms: list[str] | None = None
    allowed_digest_algorithms: list[str] | None = None
    allowed_key_encryption_algorithms: list[str] | None = None
    allowed_data_encryption_algorithms: list[str] | None = None


@dataclass(slots=True)
class ConfigAlgorithmValidationOptions:
    on_deprecated: str = "warn"
    allowed_signature_algorithms: list[str] | None = None
    allowed_digest_algorithms: list[str] | None = None


def _coerce_options(
    options: AlgorithmValidationOptions | dict[str, Any] | None,
) -> AlgorithmValidationOptions:
    if options is None:
        return AlgorithmValidationOptions()
    if isinstance(options, AlgorithmValidationOptions):
        return options
    return AlgorithmValidationOptions(
        on_deprecated=options.get("onDeprecated", options.get("on_deprecated", "warn")),
        allowed_signature_algorithms=options.get(
            "allowedSignatureAlgorithms", options.get("allowed_signature_algorithms")
        ),
        allowed_digest_algorithms=options.get(
            "allowedDigestAlgorithms", options.get("allowed_digest_algorithms")
        ),
        allowed_key_encryption_algorithms=options.get(
            "allowedKeyEncryptionAlgorithms",
            options.get("allowed_key_encryption_algorithms"),
        ),
        allowed_data_encryption_algorithms=options.get(
            "allowedDataEncryptionAlgorithms",
            options.get("allowed_data_encryption_algorithms"),
        ),
    )


def _coerce_config_options(
    options: ConfigAlgorithmValidationOptions | dict[str, Any] | None,
) -> ConfigAlgorithmValidationOptions:
    if options is None:
        return ConfigAlgorithmValidationOptions()
    if isinstance(options, ConfigAlgorithmValidationOptions):
        return options
    return ConfigAlgorithmValidationOptions(
        on_deprecated=options.get("onDeprecated", options.get("on_deprecated", "warn")),
        allowed_signature_algorithms=options.get(
            "allowedSignatureAlgorithms", options.get("allowed_signature_algorithms")
        ),
        allowed_digest_algorithms=options.get(
            "allowedDigestAlgorithms", options.get("allowed_digest_algorithms")
        ),
    )


def _extract_encryption_algorithms(xml: str) -> dict[str, str | None]:
    try:
        parsed = parse_xml(xml)
        encrypted_key = find_node(parsed, "EncryptedKey")
        key_enc_method = (
            encrypted_key.get("EncryptionMethod") if isinstance(encrypted_key, dict) else None
        )
        key_alg = key_enc_method.get("@_Algorithm") if isinstance(key_enc_method, dict) else None

        encrypted_data = find_node(parsed, "EncryptedData")
        data_enc_method = (
            encrypted_data.get("EncryptionMethod") if isinstance(encrypted_data, dict) else None
        )
        data_alg = data_enc_method.get("@_Algorithm") if isinstance(data_enc_method, dict) else None
        return {"key_encryption": key_alg or None, "data_encryption": data_alg or None}
    except Exception:
        return {"key_encryption": None, "data_encryption": None}


def _has_encrypted_assertion(xml: str) -> bool:
    try:
        parsed = parse_xml(xml)
        return find_node(parsed, "EncryptedAssertion") is not None
    except Exception:
        return False


def _handle_deprecated_algorithm(message: str, behavior: str, error_code: str) -> None:
    if behavior == "reject":
        raise APIError(400, error_code, message=message)
    if behavior == "warn":
        logger.warning("[SAML Security Warning] %s", message)
    # "allow" -> no-op


def _validate_signature_algorithm(
    algorithm: str | None, options: AlgorithmValidationOptions
) -> None:
    if not algorithm:
        return

    if options.allowed_signature_algorithms is not None:
        if algorithm not in options.allowed_signature_algorithms:
            raise APIError(
                400,
                "SAML_ALGORITHM_NOT_ALLOWED",
                message=f"SAML signature algorithm not in allow-list: {algorithm}",
            )
        return

    if algorithm in _DEPRECATED_SIGNATURE_ALGORITHMS:
        _handle_deprecated_algorithm(
            f"SAML response uses deprecated signature algorithm: {algorithm}. "
            "Please configure your IdP to use SHA-256 or stronger.",
            options.on_deprecated,
            "SAML_DEPRECATED_ALGORITHM",
        )
        return

    if algorithm not in _SECURE_SIGNATURE_ALGORITHMS:
        raise APIError(
            400,
            "SAML_UNKNOWN_ALGORITHM",
            message=f"SAML signature algorithm not recognized: {algorithm}",
        )


def _validate_encryption_algorithms(
    algorithms: dict[str, str | None], options: AlgorithmValidationOptions
) -> None:
    key_encryption = algorithms["key_encryption"]
    data_encryption = algorithms["data_encryption"]

    if key_encryption:
        if options.allowed_key_encryption_algorithms is not None:
            if key_encryption not in options.allowed_key_encryption_algorithms:
                raise APIError(
                    400,
                    "SAML_ALGORITHM_NOT_ALLOWED",
                    message=(f"SAML key encryption algorithm not in allow-list: {key_encryption}"),
                )
        elif key_encryption in _DEPRECATED_KEY_ENCRYPTION_ALGORITHMS:
            _handle_deprecated_algorithm(
                "SAML response uses deprecated key encryption algorithm: "
                f"{key_encryption}. Please configure your IdP to use RSA-OAEP.",
                options.on_deprecated,
                "SAML_DEPRECATED_ALGORITHM",
            )

    if data_encryption:
        if options.allowed_data_encryption_algorithms is not None:
            if data_encryption not in options.allowed_data_encryption_algorithms:
                raise APIError(
                    400,
                    "SAML_ALGORITHM_NOT_ALLOWED",
                    message=(
                        f"SAML data encryption algorithm not in allow-list: {data_encryption}"
                    ),
                )
        elif data_encryption in _DEPRECATED_DATA_ENCRYPTION_ALGORITHMS:
            _handle_deprecated_algorithm(
                "SAML response uses deprecated data encryption algorithm: "
                f"{data_encryption}. Please configure your IdP to use AES-GCM.",
                options.on_deprecated,
                "SAML_DEPRECATED_ALGORITHM",
            )


def validate_saml_algorithms(
    response: dict[str, Any],
    options: AlgorithmValidationOptions | dict[str, Any] | None = None,
) -> None:
    """Validate the signature + (if present) encryption algorithms of a response.

    ``response`` carries ``sigAlg`` (or ``sig_alg``) and ``samlContent`` (or
    ``saml_content``).
    """
    opts = _coerce_options(options)
    sig_alg = response.get("sigAlg", response.get("sig_alg"))
    saml_content = response.get("samlContent", response.get("saml_content", ""))

    _validate_signature_algorithm(sig_alg, opts)

    if _has_encrypted_assertion(saml_content):
        enc_algs = _extract_encryption_algorithms(saml_content)
        _validate_encryption_algorithms(enc_algs, opts)


def validate_config_algorithms(
    config: dict[str, Any],
    options: ConfigAlgorithmValidationOptions | dict[str, Any] | None = None,
) -> None:
    """Validate the signature/digest algorithms declared in a provider config."""
    opts = _coerce_config_options(options)
    signature_algorithm = config.get("signatureAlgorithm", config.get("signature_algorithm"))
    digest_algorithm = config.get("digestAlgorithm", config.get("digest_algorithm"))

    if signature_algorithm:
        normalized = _normalize_signature_algorithm(signature_algorithm)
        if opts.allowed_signature_algorithms is not None:
            normalized_allow = [
                _normalize_signature_algorithm(a) for a in opts.allowed_signature_algorithms
            ]
            if normalized not in normalized_allow:
                raise APIError(
                    400,
                    "SAML_ALGORITHM_NOT_ALLOWED",
                    message=(f"SAML signature algorithm not in allow-list: {signature_algorithm}"),
                )
        elif normalized in _DEPRECATED_SIGNATURE_ALGORITHMS:
            _handle_deprecated_algorithm(
                "SAML config uses deprecated signature algorithm: "
                f"{signature_algorithm}. Consider using SHA-256 or stronger.",
                opts.on_deprecated,
                "SAML_DEPRECATED_CONFIG_ALGORITHM",
            )
        elif normalized not in _SECURE_SIGNATURE_ALGORITHMS:
            raise APIError(
                400,
                "SAML_UNKNOWN_ALGORITHM",
                message=(f"SAML signature algorithm not recognized: {signature_algorithm}"),
            )

    if digest_algorithm:
        normalized = _normalize_digest_algorithm(digest_algorithm)
        if opts.allowed_digest_algorithms is not None:
            normalized_allow = [
                _normalize_digest_algorithm(a) for a in opts.allowed_digest_algorithms
            ]
            if normalized not in normalized_allow:
                raise APIError(
                    400,
                    "SAML_ALGORITHM_NOT_ALLOWED",
                    message=f"SAML digest algorithm not in allow-list: {digest_algorithm}",
                )
        elif normalized in _DEPRECATED_DIGEST_ALGORITHMS:
            _handle_deprecated_algorithm(
                "SAML config uses deprecated digest algorithm: "
                f"{digest_algorithm}. Consider using SHA-256 or stronger.",
                opts.on_deprecated,
                "SAML_DEPRECATED_CONFIG_ALGORITHM",
            )
        elif normalized not in _SECURE_DIGEST_ALGORITHMS:
            raise APIError(
                400,
                "SAML_UNKNOWN_ALGORITHM",
                message=f"SAML digest algorithm not recognized: {digest_algorithm}",
            )


__all__ = [
    "AlgorithmValidationOptions",
    "ConfigAlgorithmValidationOptions",
    "DataEncryptionAlgorithm",
    "DigestAlgorithm",
    "KeyEncryptionAlgorithm",
    "SignatureAlgorithm",
    "validate_config_algorithms",
    "validate_saml_algorithms",
]
