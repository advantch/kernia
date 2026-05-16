"""In-memory SMS capture for tests."""

from __future__ import annotations

import re
from dataclasses import dataclass, field


@dataclass(slots=True)
class SentSMS:
    to: str
    body: str


_OTP_RE = re.compile(r"(?<!\d)(\d{6})(?!\d)")


@dataclass
class MockSMS:
    """Captures outgoing SMS messages."""

    sent: list[SentSMS] = field(default_factory=list)

    async def send(self, to: str, body: str) -> None:
        self.sent.append(SentSMS(to=to, body=body))

    def clear(self) -> None:
        self.sent.clear()

    def find_otp(self, to: str) -> str:
        """Extract a 6-digit OTP from the most recent message to `to`."""
        for sms in reversed(self.sent):
            if sms.to != to:
                continue
            match = _OTP_RE.search(sms.body)
            if match:
                return match.group(1)
        raise LookupError(f"no 6-digit OTP found in messages to {to!r}")


__all__ = ["MockSMS", "SentSMS"]
