"""Thin wrapper over the ``webauthn`` library mirroring ``@simplewebauthn/server``.

The upstream plugin depends on ``@simplewebauthn/server`` and the upstream test
suite mocks ``verifyRegistrationResponse`` / ``verifyAuthenticationResponse``. We
replicate that seam here so tests can monkeypatch the same two functions on this
module (``routes.py`` calls them via this module, never imports them directly).

The verification results are exposed with upstream-compatible attribute names so
the route handlers and tests can read ``verified`` / ``registration_info`` /
``authentication_info`` without caring about the underlying library's shape.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass
from typing import Any


def _b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


@dataclass
class VerifiedCredential:
    id: str
    public_key: bytes
    counter: int


@dataclass
class VerifiedRegistrationResponse:
    verified: bool
    registration_info: Any = None


@dataclass
class RegistrationInfo:
    aaguid: str
    credential_device_type: str
    credential_backed_up: bool
    credential: VerifiedCredential


@dataclass
class VerifiedAuthenticationResponse:
    verified: bool
    authentication_info: Any = None


@dataclass
class AuthenticationInfo:
    new_counter: int


def generate_registration_options(**kwargs: Any) -> Any:
    """Proxy to ``webauthn.generate_registration_options``."""
    from webauthn import generate_registration_options as _gen

    return _gen(**kwargs)


def generate_authentication_options(**kwargs: Any) -> Any:
    """Proxy to ``webauthn.generate_authentication_options``."""
    from webauthn import generate_authentication_options as _gen

    return _gen(**kwargs)


def verify_registration_response(
    *,
    response: Any,
    expected_challenge: bytes,
    expected_origin: str | list[str],
    expected_rpid: str,
    require_user_verification: bool = False,
) -> VerifiedRegistrationResponse:
    """Verify an attestation, returning an upstream-shaped result.

    Tests monkeypatch this function on the module (mirroring the vitest
    ``vi.mock`` of ``verifyRegistrationResponse``).
    """
    from webauthn import verify_registration_response as _verify

    result = _verify(
        credential=response,
        expected_challenge=expected_challenge,
        expected_origin=expected_origin,
        expected_rp_id=expected_rpid,
        require_user_verification=require_user_verification,
    )
    return VerifiedRegistrationResponse(
        verified=True,
        registration_info=RegistrationInfo(
            aaguid=str(getattr(result, "aaguid", "") or ""),
            credential_device_type=getattr(
                result.credential_device_type, "value", str(result.credential_device_type)
            ),
            credential_backed_up=bool(result.credential_backed_up),
            credential=VerifiedCredential(
                id=_b64url(result.credential_id),
                public_key=result.credential_public_key,
                counter=int(result.sign_count),
            ),
        ),
    )


def verify_authentication_response(
    *,
    response: Any,
    expected_challenge: bytes,
    expected_origin: str | list[str],
    expected_rpid: str,
    credential: dict,
    require_user_verification: bool = False,
) -> VerifiedAuthenticationResponse:
    """Verify an assertion, returning an upstream-shaped result.

    Tests monkeypatch this function on the module.
    """
    from webauthn import verify_authentication_response as _verify

    result = _verify(
        credential=response,
        expected_challenge=expected_challenge,
        expected_origin=expected_origin,
        expected_rp_id=expected_rpid,
        credential_public_key=credential["public_key"],
        credential_current_sign_count=int(credential["counter"]),
        require_user_verification=require_user_verification,
    )
    return VerifiedAuthenticationResponse(
        verified=True,
        authentication_info=AuthenticationInfo(new_counter=int(result.new_sign_count)),
    )


__all__ = [
    "AuthenticationInfo",
    "RegistrationInfo",
    "VerifiedAuthenticationResponse",
    "VerifiedCredential",
    "VerifiedRegistrationResponse",
    "generate_authentication_options",
    "generate_registration_options",
    "verify_authentication_response",
    "verify_registration_response",
]
