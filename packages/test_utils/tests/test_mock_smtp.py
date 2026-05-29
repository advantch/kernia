"""MockSMTP: send / clear / find_link."""

from __future__ import annotations

import pytest
from better_auth_test_utils import MockSMTP, SentEmail


async def test_send_captures_messages() -> None:
    smtp = MockSMTP()
    await smtp.send(SentEmail(to="a@b.c", subject="hi", body="hello"))
    await smtp.send(SentEmail(to="d@e.f", subject="bye", body="goodbye"))
    assert len(smtp.sent) == 2
    assert smtp.sent[0].to == "a@b.c"
    assert smtp.sent[1].subject == "bye"


async def test_clear_resets() -> None:
    smtp = MockSMTP()
    await smtp.send(SentEmail(to="a@b.c", body="x"))
    smtp.clear()
    assert smtp.sent == []


async def test_find_link_returns_first_match_in_body() -> None:
    smtp = MockSMTP()
    await smtp.send(
        SentEmail(
            to="user@example.com",
            subject="Verify",
            body="Click here: https://app.test/verify?token=abc to continue.",
        )
    )
    url = smtp.find_link("user@example.com", contains="/verify")
    assert url == "https://app.test/verify?token=abc"


async def test_find_link_falls_back_to_html() -> None:
    smtp = MockSMTP()
    await smtp.send(
        SentEmail(
            to="u@x",
            body="no link in plain text",
            html='<a href="https://app.test/reset?t=xyz">click</a>',
        )
    )
    url = smtp.find_link("u@x", contains="/reset")
    assert url == "https://app.test/reset?t=xyz"


async def test_find_link_raises_when_missing() -> None:
    smtp = MockSMTP()
    await smtp.send(SentEmail(to="u@x", body="no urls here"))
    with pytest.raises(LookupError):
        smtp.find_link("u@x", contains="/verify")
