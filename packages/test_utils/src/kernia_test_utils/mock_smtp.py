"""In-memory SMTP capture for tests.

Plugins (email-verification, magic-link, password reset, etc.) accept a `send`
callable; tests pass `MockSMTP().send` and then assert on the captured messages.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any


@dataclass(slots=True)
class SentEmail:
    to: str
    subject: str = ""
    body: str = ""
    html: str | None = None
    from_addr: str | None = None
    headers: dict[str, str] = field(default_factory=dict)
    meta: dict[str, Any] = field(default_factory=dict)


_URL_RE = re.compile(r"https?://[^\s<>\"'\)]+", re.IGNORECASE)


@dataclass
class MockSMTP:
    """Captures outgoing emails. The `send` method is async to match real
    plugin contracts."""

    sent: list[SentEmail] = field(default_factory=list)

    async def send(self, email: SentEmail) -> None:
        self.sent.append(email)

    def clear(self) -> None:
        self.sent.clear()

    def find_link(self, to: str, contains: str = "/verify") -> str:
        """Return the first URL containing `contains` from emails sent to `to`.

        Searches the plain body, then the HTML alternative. Raises LookupError
        if no matching link is found — tests should treat that as a failure.
        """
        for email in self.sent:
            if email.to != to:
                continue
            for source in (email.body, email.html or ""):
                for match in _URL_RE.finditer(source):
                    url = match.group(0)
                    if contains in url:
                        return url
        raise LookupError(
            f"no link containing {contains!r} found in {len(self.sent)} captured emails to {to!r}"
        )


__all__ = ["MockSMTP", "SentEmail"]
