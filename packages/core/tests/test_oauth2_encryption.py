"""Unit tests for kernia.oauth2.encryption — AES-GCM token encryption."""

from __future__ import annotations

import pytest
from kernia.oauth2.encryption import decrypt_token, encrypt_token, is_encrypted


def test_round_trip() -> None:
    ct = encrypt_token("access-token-value", secret="cookie-secret")
    assert is_encrypted(ct)
    assert ct != "access-token-value"
    assert decrypt_token(ct, secret="cookie-secret") == "access-token-value"


def test_wrong_secret_fails() -> None:
    ct = encrypt_token("v", secret="s1")
    with pytest.raises(ValueError, match="tag verification"):
        decrypt_token(ct, secret="s2")


def test_tampered_ciphertext_fails() -> None:
    ct = encrypt_token("v", secret="s")
    body = ct.rsplit(".", 1)[1]
    tampered = ct[: -(len(body))] + ("A" if body[0] != "A" else "B") + body[1:]
    with pytest.raises(ValueError, match="tag verification"):
        decrypt_token(tampered, secret="s")


def test_non_encrypted_input_rejected() -> None:
    with pytest.raises(ValueError, match="not an encrypted token"):
        decrypt_token("plaintext-token", secret="s")


def test_is_encrypted_recognizes_prefix() -> None:
    assert is_encrypted("enc.v1.xxx.yyy")
    assert not is_encrypted("not-encrypted")


def test_distinct_nonces_per_call() -> None:
    a = encrypt_token("same", secret="s")
    b = encrypt_token("same", secret="s")
    assert a != b  # fresh nonce
    assert decrypt_token(a, secret="s") == decrypt_token(b, secret="s") == "same"
