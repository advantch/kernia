"""SAML assertion timestamp validation (NotBefore / NotOnOrAfter).

1:1 port of ``reference/packages/sso/src/saml/timestamp.ts``.

Clock-skew tolerance is expressed in milliseconds to match the upstream
``DEFAULT_CLOCK_SKEW_MS`` constant and the ``clockSkew`` option semantics.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Protocol

from kernia.error import APIError

logger = logging.getLogger("kernia.sso.saml")

# Mirror of constants.DEFAULT_CLOCK_SKEW_MS (5 minutes, in milliseconds).
DEFAULT_CLOCK_SKEW_MS = 5 * 60 * 1000


class _Logger(Protocol):
    def warn(self, message: str, data: dict[str, Any] | None = ...) -> None: ...


@dataclass(frozen=True)
class SAMLConditions:
    """Conditions extracted from a SAML assertion."""

    not_before: str | None = None
    not_on_or_after: str | None = None


@dataclass(frozen=True)
class TimestampValidationOptions:
    """Options controlling timestamp validation."""

    clock_skew: int | None = None
    require_timestamps: bool = False
    logger: _Logger | None = None


def _now_ms() -> int:
    return int(datetime.now(tz=UTC).timestamp() * 1000)


def _parse_ms(value: str) -> float:
    """Parse an ISO-8601 / RFC-3339 timestamp into epoch milliseconds.

    Returns NaN (``float('nan')``) when the value cannot be parsed, mirroring
    the JS ``new Date(...).getTime()`` -> ``NaN`` contract.
    """
    text = value.strip()
    # JS Date accepts a trailing "Z"; Python's fromisoformat (3.11+) does too,
    # but normalise defensively for older behaviour.
    normalised = text.replace("Z", "+00:00") if text.endswith("Z") else text
    try:
        dt = datetime.fromisoformat(normalised)
    except ValueError:
        return float("nan")
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt.timestamp() * 1000


def validate_saml_timestamp(
    conditions: SAMLConditions | None,
    options: TimestampValidationOptions | None = None,
) -> None:
    """Validate NotBefore / NotOnOrAfter conditions of a SAML assertion.

    Raises ``APIError`` (BAD_REQUEST) for missing-but-required, unparseable,
    not-yet-valid, or expired timestamps.
    """
    opts = options or TimestampValidationOptions()
    clock_skew = opts.clock_skew if opts.clock_skew is not None else DEFAULT_CLOCK_SKEW_MS

    not_before = conditions.not_before if conditions else None
    not_on_or_after = conditions.not_on_or_after if conditions else None
    has_timestamps = bool(not_before) or bool(not_on_or_after)

    if not has_timestamps:
        if opts.require_timestamps:
            raise APIError(
                400,
                "BAD_REQUEST",
                "SAML assertion missing required timestamp conditions",
                {
                    "details": (
                        "Assertions must include NotBefore and/or "
                        "NotOnOrAfter conditions"
                    )
                },
            )
        if opts.logger is not None:
            opts.logger.warn(
                "SAML assertion accepted without timestamp conditions",
                {"hasConditions": conditions is not None},
            )
        else:
            logger.warning(
                "SAML assertion accepted without timestamp conditions "
                "(hasConditions=%s)",
                conditions is not None,
            )
        return

    now = _now_ms()

    if not_before:
        not_before_time = _parse_ms(not_before)
        if not_before_time != not_before_time:  # NaN check
            raise APIError(
                400,
                "BAD_REQUEST",
                "SAML assertion has invalid NotBefore timestamp",
                {"details": f"Unable to parse NotBefore value: {not_before}"},
            )
        if now < not_before_time - clock_skew:
            raise APIError(
                400,
                "BAD_REQUEST",
                "SAML assertion is not yet valid",
                {
                    "details": (
                        f"Current time is before NotBefore (with {clock_skew}ms "
                        "clock skew tolerance)"
                    )
                },
            )

    if not_on_or_after:
        not_on_or_after_time = _parse_ms(not_on_or_after)
        if not_on_or_after_time != not_on_or_after_time:  # NaN check
            raise APIError(
                400,
                "BAD_REQUEST",
                "SAML assertion has invalid NotOnOrAfter timestamp",
                {"details": f"Unable to parse NotOnOrAfter value: {not_on_or_after}"},
            )
        if now > not_on_or_after_time + clock_skew:
            raise APIError(
                400,
                "BAD_REQUEST",
                "SAML assertion has expired",
                {
                    "details": (
                        f"Current time is after NotOnOrAfter (with {clock_skew}ms "
                        "clock skew tolerance)"
                    )
                },
            )


__all__ = [
    "DEFAULT_CLOCK_SKEW_MS",
    "SAMLConditions",
    "TimestampValidationOptions",
    "validate_saml_timestamp",
]
