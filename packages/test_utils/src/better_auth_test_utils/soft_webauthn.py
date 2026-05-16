"""Software WebAuthn authenticator for tests.

Generates real ES256 keypairs, produces fmt:"none" attestation objects, and
signs authentication assertions exactly the way a hardware authenticator does.
The `webauthn` library accepts the output of these methods unchanged — letting
us round-trip the full register + authenticate flow without any browser or
hardware token.

Wire format references:
  WebAuthn L3 §6.1 (authenticatorData)
  WebAuthn L3 §6.5 (attestation)
  RFC 8152 (COSE Keys)

This is a test fixture; not for production use.
"""

from __future__ import annotations

import hashlib
import os
import struct
from dataclasses import dataclass, field
from typing import Any

import cbor2
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
    encode_dss_signature,
)
from webauthn.helpers import base64url_to_bytes, bytes_to_base64url


# WebAuthn authenticator-data flags
_FLAG_UP = 0x01   # user present
_FLAG_UV = 0x04   # user verified
_FLAG_AT = 0x40   # attested credential data included (registration only)
_FLAG_BE = 0x08   # backup eligible
_FLAG_BS = 0x10   # backup state


@dataclass
class _Credential:
    credential_id: bytes
    private_key: ec.EllipticCurvePrivateKey
    public_key: ec.EllipticCurvePublicKey
    sign_count: int = 0


@dataclass
class SoftAuthenticator:
    """A single in-memory WebAuthn authenticator.

    Holds one or more credentials. `register(...)` builds an attestation
    response; `authenticate(...)` builds an assertion. Both methods return
    plain dicts in the shape `webauthn.verify_*` consumes.
    """

    aaguid: bytes = b"\x00" * 16
    credentials: dict[str, _Credential] = field(default_factory=dict)

    # ---------------------------- registration ----------------------------

    def register(
        self,
        *,
        challenge: bytes,
        origin: str,
        rp_id: str,
        user_present: bool = True,
        user_verified: bool = True,
        backup_eligible: bool = True,
        backup_state: bool = False,
    ) -> dict[str, Any]:
        """Build a PublicKeyCredential (attestation) for a fresh credential.

        Returns a dict matching the WebAuthn JSON serialization used by
        `webauthn.verify_registration_response`.
        """
        # 1. Fresh credential
        cred_id = os.urandom(16)
        priv = ec.generate_private_key(ec.SECP256R1())
        pub = priv.public_key()

        # 2. clientDataJSON
        client_data = self._client_data("webauthn.create", challenge, origin)

        # 3. attestedCredentialData
        # AAGUID || credentialIdLength(2) || credentialId || credentialPublicKey(COSE)
        cose_key = _ec_public_key_to_cose(pub)
        cose_cbor = cbor2.dumps(cose_key)
        attested = (
            self.aaguid
            + struct.pack(">H", len(cred_id))
            + cred_id
            + cose_cbor
        )

        # 4. authData
        flags = _FLAG_UP * int(user_present) | _FLAG_UV * int(user_verified) | _FLAG_AT
        if backup_eligible:
            flags |= _FLAG_BE
        if backup_state:
            flags |= _FLAG_BS
        auth_data = _build_auth_data(rp_id, flags, 0) + attested

        # 5. attestationObject = CBOR({fmt: "none", attStmt: {}, authData})
        att_obj = cbor2.dumps({"fmt": "none", "attStmt": {}, "authData": auth_data})

        # 6. Persist for later authentication
        cred_id_b64 = bytes_to_base64url(cred_id)
        self.credentials[cred_id_b64] = _Credential(
            credential_id=cred_id,
            private_key=priv,
            public_key=pub,
            sign_count=0,
        )

        return {
            "id": cred_id_b64,
            "rawId": cred_id_b64,
            "type": "public-key",
            "response": {
                "clientDataJSON": bytes_to_base64url(client_data),
                "attestationObject": bytes_to_base64url(att_obj),
                "transports": ["internal"],
            },
            "clientExtensionResults": {},
            "authenticatorAttachment": "platform",
        }

    # --------------------------- authentication ---------------------------

    def authenticate(
        self,
        *,
        challenge: bytes,
        origin: str,
        rp_id: str,
        credential_id: str | None = None,
        user_present: bool = True,
        user_verified: bool = True,
    ) -> dict[str, Any]:
        """Build a PublicKeyCredential (assertion) signing this challenge.

        Picks the credential by `credential_id` (base64url) if given; otherwise
        the first registered credential. Returns the WebAuthn JSON shape used
        by `webauthn.verify_authentication_response`.
        """
        if credential_id is not None:
            cred = self.credentials[credential_id]
        else:
            cred = next(iter(self.credentials.values()))

        cred.sign_count += 1

        client_data = self._client_data("webauthn.get", challenge, origin)
        client_data_hash = hashlib.sha256(client_data).digest()

        flags = _FLAG_UP * int(user_present) | _FLAG_UV * int(user_verified)
        auth_data = _build_auth_data(rp_id, flags, cred.sign_count)

        # ES256 signs the concatenation
        sig_input = auth_data + client_data_hash
        der_sig = cred.private_key.sign(sig_input, ec.ECDSA(hashes.SHA256()))

        cred_id_b64 = bytes_to_base64url(cred.credential_id)
        return {
            "id": cred_id_b64,
            "rawId": cred_id_b64,
            "type": "public-key",
            "response": {
                "clientDataJSON": bytes_to_base64url(client_data),
                "authenticatorData": bytes_to_base64url(auth_data),
                "signature": bytes_to_base64url(der_sig),
                "userHandle": None,
            },
            "clientExtensionResults": {},
            "authenticatorAttachment": "platform",
        }

    # ----------------------------- helpers --------------------------------

    def _client_data(self, type_: str, challenge: bytes, origin: str) -> bytes:
        import json

        return json.dumps(
            {
                "type": type_,
                "challenge": bytes_to_base64url(challenge),
                "origin": origin,
                "crossOrigin": False,
            },
            separators=(",", ":"),
        ).encode("utf-8")


def _build_auth_data(rp_id: str, flags: int, sign_count: int) -> bytes:
    rp_id_hash = hashlib.sha256(rp_id.encode("utf-8")).digest()
    return rp_id_hash + bytes([flags]) + struct.pack(">I", sign_count)


def _ec_public_key_to_cose(pub: ec.EllipticCurvePublicKey) -> dict[int, Any]:
    """COSE_Key map for an EC2 P-256 public key (RFC 8152 §13.1.1).

    Map labels:
        1 (kty) = 2 (EC2)
       -1 (crv) = 1 (P-256)
       -2 (x)   = 32-byte big-endian
       -3 (y)   = 32-byte big-endian
        3 (alg) = -7 (ES256)
    """
    numbers = pub.public_numbers()
    x = numbers.x.to_bytes(32, "big")
    y = numbers.y.to_bytes(32, "big")
    return {1: 2, 3: -7, -1: 1, -2: x, -3: y}


__all__ = ["SoftAuthenticator"]
