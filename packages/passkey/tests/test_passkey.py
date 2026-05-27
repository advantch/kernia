"""Unit tests for the passkey plugin.

Producing a forged but cryptographically valid attestation/assertion from pure
Python is non-trivial without an authenticator simulator (we'd need to emit
CBOR-encoded attestation objects signed with the same trust path the
`webauthn` library checks). We therefore restrict these tests to:

  * schema registration
  * the discovery round-trip: register/start returns a valid options dict and
    persists a verification row that the verifier looks up
  * error envelope shape (PASSKEY_NOT_FOUND, INVALID_PASSKEY_CHALLENGE)

A full webauthn integration test belongs in `e2e/integration/` once we have a
softWebAuthn-style authenticator harness.
"""

from __future__ import annotations

import base64
import json

import pytest

from kernia.auth import init
from kernia.plugins import email_and_password
from kernia.types.adapter import Where
from kernia.types.init_options import KerniaOptions
from kernia_memory_adapter import memory_adapter
from kernia_passkey import passkey
from kernia_test_utils import ASGIDriver


def _build() -> tuple[ASGIDriver, object]:
    adapter = memory_adapter()
    auth = init(
        KerniaOptions(
            database=adapter,
            secret="test-secret-key",
            plugins=[
                email_and_password(),
                passkey(rp_id="localhost", rp_name="Test", origin="http://localhost:3000"),
            ],
        )
    )
    return ASGIDriver(app=auth.router.mount()), adapter


def test_passkey_plugin_schema_registers_table() -> None:
    from kernia_passkey import passkey as make

    p = make(rp_id="localhost", rp_name="t", origin="http://localhost")
    assert p.schema is not None
    table_names = {m.name for m in p.schema.tables}
    assert "passkey" in table_names
    pass_model = next(m for m in p.schema.tables if m.name == "passkey")
    field_names = {f.name for f in pass_model.fields}
    assert {"credentialId", "publicKey", "counter", "userId"} <= field_names


async def test_register_start_returns_options_and_persists_challenge() -> None:
    driver, adapter = _build()
    r = await driver.request(
        "POST",
        "/sign-up/email",
        json_body={"email": "pk@example.com", "password": "correcthorse"},
    )
    assert r.status == 200
    user_id = r.json()["user"]["id"]

    r = await driver.request("POST", "/passkey/register/start", json_body={})
    assert r.status == 200, r.json()
    options = r.json()["options"]
    # Spec round-trip: options must carry the required WebAuthn fields.
    assert options["rp"]["id"] == "localhost"
    assert options["rp"]["name"] == "Test"
    assert options["user"]["id"]  # base64url
    assert options["challenge"]
    # And we persisted a verification row to consume on /finish.
    pending = await adapter.find_one(  # type: ignore[attr-defined]
        model="verification",
        where=(Where(field="identifier", value=f"passkey-reg:{user_id}"),),
    )
    assert pending is not None


async def test_authenticate_start_anon_returns_discoverable_options() -> None:
    driver, _ = _build()
    r = await driver.request("POST", "/passkey/authenticate/start", json_body={})
    assert r.status == 200, r.json()
    options = r.json()["options"]
    assert options["rpId"] == "localhost"
    assert options["challenge"]


async def test_delete_passkey_unknown_returns_404() -> None:
    driver, _ = _build()
    await driver.request(
        "POST",
        "/sign-up/email",
        json_body={"email": "del@example.com", "password": "correcthorse"},
    )
    r = await driver.request(
        "POST", "/passkey/delete", json_body={"credential_id": "does-not-exist"}
    )
    assert r.status == 404
    assert r.json()["code"] == "PASSKEY_NOT_FOUND"


async def test_register_finish_with_garbage_attestation_rejected() -> None:
    """Smoke-check the attestation-verify error envelope.

    We can't produce a real attestation, but we can prove the endpoint
    declines the wrong shape with the documented error code (and that the
    challenge row gating it exists)."""
    driver, _ = _build()
    await driver.request(
        "POST",
        "/sign-up/email",
        json_body={"email": "rf@example.com", "password": "correcthorse"},
    )
    # Start so the challenge row exists.
    await driver.request("POST", "/passkey/register/start", json_body={})
    bogus = {
        "id": base64.urlsafe_b64encode(b"abc").rstrip(b"=").decode(),
        "rawId": base64.urlsafe_b64encode(b"abc").rstrip(b"=").decode(),
        "response": {
            "clientDataJSON": base64.urlsafe_b64encode(b"{}").rstrip(b"=").decode(),
            "attestationObject": base64.urlsafe_b64encode(b"nope").rstrip(b"=").decode(),
        },
        "type": "public-key",
    }
    r = await driver.request(
        "POST", "/passkey/register/finish", json_body={"response": bogus}
    )
    assert r.status == 400
    assert r.json()["code"] == "INVALID_PASSKEY_ATTESTATION"


def test_options_dict_includes_required_fields() -> None:
    """Pure unit: the webauthn library exposes register options we can
    round-trip into JSON without touching our plugin endpoints. Locks in the
    library API version we coded against."""
    from webauthn import generate_registration_options, options_to_json

    options = generate_registration_options(
        rp_id="localhost", rp_name="t", user_name="u", user_id=b"u"
    )
    payload = json.loads(options_to_json(options))
    assert payload["rp"]["id"] == "localhost"
    assert payload["user"]["id"]
