"""MockSMS: send / clear / find_otp."""

from __future__ import annotations

import pytest
from kernia_test_utils import MockSMS


async def test_send_captures() -> None:
    sms = MockSMS()
    await sms.send("+1555", "your code is 123456")
    assert len(sms.sent) == 1
    assert sms.sent[0].to == "+1555"
    assert "123456" in sms.sent[0].body


async def test_clear_resets() -> None:
    sms = MockSMS()
    await sms.send("+1555", "code: 111111")
    sms.clear()
    assert sms.sent == []


async def test_find_otp_returns_latest_match() -> None:
    sms = MockSMS()
    await sms.send("+1555", "first: 111111")
    await sms.send("+1555", "second: 222222")
    await sms.send("+1666", "other: 333333")
    assert sms.find_otp("+1555") == "222222"
    assert sms.find_otp("+1666") == "333333"


async def test_find_otp_raises_when_missing() -> None:
    sms = MockSMS()
    await sms.send("+1555", "no digits here")
    with pytest.raises(LookupError):
        sms.find_otp("+1555")


async def test_find_otp_ignores_longer_digit_runs() -> None:
    sms = MockSMS()
    # 12-digit account number should NOT match.
    await sms.send("+1555", "account 123456789012 ok")
    with pytest.raises(LookupError):
        sms.find_otp("+1555")
