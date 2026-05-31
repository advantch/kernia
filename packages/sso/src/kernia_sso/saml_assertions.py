"""SAML assertion counting and single-assertion validation.

1:1 port of ``reference/packages/sso/src/saml/assertions.ts``.

Counts ``Assertion`` / ``EncryptedAssertion`` nodes anywhere in the parsed XML
tree (XML Signature Wrapping defence) and enforces that a decoded SAML response
contains exactly one assertion.
"""

from __future__ import annotations

import base64
import binascii
import re
from dataclasses import dataclass

from better_auth.error import APIError

from .saml_parser import count_all_nodes, parse_xml

_WHITESPACE_RE = re.compile(r"\s+")


@dataclass(frozen=True)
class AssertionCounts:
    """Mirror of the TS ``AssertionCounts`` interface."""

    assertions: int
    encrypted_assertions: int
    total: int


def count_assertions(xml: str) -> AssertionCounts:
    """Count ``Assertion`` and ``EncryptedAssertion`` nodes in *xml*.

    Raises ``APIError(SAML_INVALID_XML)`` when the XML cannot be parsed.
    """
    try:
        parsed = parse_xml(xml)
    except Exception as exc:  # - matches TS broad catch
        raise APIError(
            400,
            "SAML_INVALID_XML",
            "Failed to parse SAML response XML",
        ) from exc

    assertions = count_all_nodes(parsed, "Assertion")
    encrypted_assertions = count_all_nodes(parsed, "EncryptedAssertion")

    return AssertionCounts(
        assertions=assertions,
        encrypted_assertions=encrypted_assertions,
        total=assertions + encrypted_assertions,
    )


def validate_single_assertion(saml_response: str) -> None:
    """Decode *saml_response* (base64) and enforce exactly one assertion.

    Raises ``APIError`` with codes ``SAML_INVALID_ENCODING``,
    ``SAML_NO_ASSERTION`` or ``SAML_MULTIPLE_ASSERTIONS`` to match upstream.
    """
    try:
        stripped = _WHITESPACE_RE.sub("", saml_response)
        # validate=True rejects non-base64 alphabet characters (e.g. "!!!").
        decoded = base64.b64decode(stripped, validate=True)
        xml = decoded.decode("utf-8")
        if "<" not in xml:
            raise ValueError("Not XML")
    except (ValueError, binascii.Error, UnicodeDecodeError) as exc:
        raise APIError(
            400,
            "SAML_INVALID_ENCODING",
            "Invalid base64-encoded SAML response",
        ) from exc

    counts = count_assertions(xml)

    if counts.total == 0:
        raise APIError(
            400,
            "SAML_NO_ASSERTION",
            "SAML response contains no assertions",
        )

    if counts.total > 1:
        raise APIError(
            400,
            "SAML_MULTIPLE_ASSERTIONS",
            f"SAML response contains {counts.total} assertions, expected exactly 1",
        )


__all__ = ["AssertionCounts", "count_assertions", "validate_single_assertion"]
