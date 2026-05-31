"""Tiny in-process event bus.

Lets plugins emit/subscribe to lifecycle signals without taking hard imports on
each other. The bus is per-`AuthContext` and stored at
`auth.plugin_state["events"]` so that plugins can find it without touching the
context dataclass.

Events are best-effort: handlers run sequentially under the caller's task; an
exception in one handler is logged and other handlers still run. We deliberately
do not introduce an event queue or background workers — auth plugins want to
react in the same request lifecycle as the change that triggered them.

Standard event names (str constants):

  * ``organization.member.added``    payload: ``MemberEvent``
  * ``organization.member.removed``  payload: ``MemberEvent``
  * ``organization.member.updated``  payload: ``MemberEvent`` (role change)
  * ``user.deleted``                 payload: ``UserEvent``
"""

from __future__ import annotations

import logging
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any

_log = logging.getLogger("kernia.events")

Handler = Callable[[Any], Awaitable[None]]


@dataclass(frozen=True, slots=True)
class MemberEvent:
    """Payload for organization.member.{added,removed,updated} events."""

    organization_id: str
    user_id: str
    role: str
    action: str  # "added" | "removed" | "updated"


@dataclass(frozen=True, slots=True)
class UserEvent:
    """Payload for user.* events."""

    user_id: str
    action: str  # "deleted"


@dataclass
class EventBus:
    """A minimal pub/sub bus. Subscribers are async callables."""

    _subs: dict[str, list[Handler]] = field(default_factory=dict)

    def on(self, event: str, handler: Handler) -> None:
        self._subs.setdefault(event, []).append(handler)

    async def emit(self, event: str, payload: Any) -> None:
        for handler in self._subs.get(event, ()):
            try:
                await handler(payload)
            except Exception:
                _log.exception("event handler for %s raised", event)


def get_bus(auth: Any) -> EventBus:
    """Return the bus attached to an `AuthContext` (creating one on first call)."""
    bus = auth.plugin_state.get("events")
    if bus is None:
        bus = EventBus()
        auth.plugin_state["events"] = bus
    return bus


__all__ = ["EventBus", "MemberEvent", "UserEvent", "get_bus"]
