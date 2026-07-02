"""1:1 port of the "SAML SSO - Timestamp Validation" suite in
reference/packages/sso/src/saml.test.ts.

The TS suite calls ``validateSAMLTimestamp({ notBefore, notOnOrAfter }, opts)``
with camelCase keys. The Python port takes a :class:`SAMLConditions` dataclass
and :class:`TimestampValidationOptions`; a small helper mirrors the TS call
shape. Boundary tests freeze the clock by monkeypatching ``_now_ms`` instead of
``vi.useFakeTimers()``.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from kernia.error import APIError
from kernia_sso import saml_timestamp
from kernia_sso.saml_timestamp import (
    DEFAULT_CLOCK_SKEW_MS,
    SAMLConditions,
    TimestampValidationOptions,
    validate_saml_timestamp,
)


def _iso(dt: datetime) -> str:
    return dt.astimezone(UTC).isoformat()


def _now() -> datetime:
    return datetime.now(tz=UTC)


def _validate(conditions, options=None) -> None:
    """Mirror the TS ``validateSAMLTimestamp(conditions, options)`` call shape.

    ``conditions`` may be ``None``, ``{}`` or a dict with camelCase keys.
    ``options`` may be ``None`` or a dict with camelCase keys.
    """
    if conditions is None:
        cond = None
    else:
        cond = SAMLConditions(
            not_before=conditions.get("notBefore"),
            not_on_or_after=conditions.get("notOnOrAfter"),
        )
    if options is None:
        opts = None
    else:
        opts = TimestampValidationOptions(
            clock_skew=options.get("clockSkew"),
            require_timestamps=options.get("requireTimestamps", False),
        )
    validate_saml_timestamp(cond, opts)


# --------------------------------------------------------------------------- #
# Valid assertions within time window
# --------------------------------------------------------------------------- #
class TestValidAssertionsWithinTimeWindow:
    def test_accept_current_not_before_and_future_not_on_or_after(self) -> None:
        now = _now()
        five_minutes_from_now = now + timedelta(minutes=5)
        _validate(
            {
                "notBefore": _iso(now),
                "notOnOrAfter": _iso(five_minutes_from_now),
            }
        )

    def test_accept_within_clock_skew_tolerance(self) -> None:
        two_minutes_ago = _iso(_now() - timedelta(minutes=2))
        _validate({"notOnOrAfter": two_minutes_ago})

    def test_accept_not_before_slightly_in_future_within_skew(self) -> None:
        two_minutes_from_now = _iso(_now() + timedelta(minutes=2))
        _validate({"notBefore": two_minutes_from_now})


# --------------------------------------------------------------------------- #
# NotBefore validation (future-dated assertions)
# --------------------------------------------------------------------------- #
class TestNotBeforeValidation:
    def test_reject_not_before_too_far_in_future(self) -> None:
        ten_minutes_from_now = _iso(_now() + timedelta(minutes=10))
        with pytest.raises(APIError, match="SAML assertion is not yet valid"):
            _validate({"notBefore": ten_minutes_from_now})

    def test_reject_with_custom_strict_clock_skew(self) -> None:
        three_seconds_from_now = _iso(_now() + timedelta(seconds=3))
        with pytest.raises(APIError, match="SAML assertion is not yet valid"):
            _validate({"notBefore": three_seconds_from_now}, {"clockSkew": 1000})


# --------------------------------------------------------------------------- #
# NotOnOrAfter validation (expired assertions)
# --------------------------------------------------------------------------- #
class TestNotOnOrAfterValidation:
    def test_reject_expired_assertion(self) -> None:
        ten_minutes_ago = _iso(_now() - timedelta(minutes=10))
        with pytest.raises(APIError, match="SAML assertion has expired"):
            _validate({"notOnOrAfter": ten_minutes_ago})

    def test_reject_with_custom_strict_clock_skew(self) -> None:
        three_seconds_ago = _iso(_now() - timedelta(seconds=3))
        with pytest.raises(APIError, match="SAML assertion has expired"):
            _validate({"notOnOrAfter": three_seconds_ago}, {"clockSkew": 1000})


# --------------------------------------------------------------------------- #
# Boundary conditions (exactly at window edges)
# --------------------------------------------------------------------------- #
class TestBoundaryConditions:
    FIXED_TIME_MS = int(datetime(2024, 1, 15, 12, 0, 0, tzinfo=UTC).timestamp() * 1000)

    @pytest.fixture(autouse=True)
    def _freeze_clock(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(saml_timestamp, "_now_ms", lambda: self.FIXED_TIME_MS)

    def _iso_from_ms(self, ms: int) -> str:
        return _iso(datetime.fromtimestamp(ms / 1000, tz=UTC))

    def test_accept_expiring_exactly_at_clock_skew_boundary(self) -> None:
        exactly = self._iso_from_ms(self.FIXED_TIME_MS - DEFAULT_CLOCK_SKEW_MS)
        _validate({"notOnOrAfter": exactly})

    def test_reject_expiring_1ms_beyond_clock_skew_boundary(self) -> None:
        just_past = self._iso_from_ms(self.FIXED_TIME_MS - DEFAULT_CLOCK_SKEW_MS - 1)
        with pytest.raises(APIError, match="SAML assertion has expired"):
            _validate({"notOnOrAfter": just_past})

    def test_accept_not_before_exactly_at_clock_skew_boundary(self) -> None:
        exactly = self._iso_from_ms(self.FIXED_TIME_MS + DEFAULT_CLOCK_SKEW_MS)
        _validate({"notBefore": exactly})

    def test_reject_not_before_1ms_beyond_clock_skew_boundary(self) -> None:
        just_past = self._iso_from_ms(self.FIXED_TIME_MS + DEFAULT_CLOCK_SKEW_MS + 1)
        with pytest.raises(APIError, match="SAML assertion is not yet valid"):
            _validate({"notBefore": just_past})


# --------------------------------------------------------------------------- #
# Missing timestamps behavior
# --------------------------------------------------------------------------- #
class TestMissingTimestampsBehavior:
    def test_accept_missing_timestamps_when_not_required(self) -> None:
        _validate(None, {"requireTimestamps": False})

    def test_accept_empty_conditions_when_not_required(self) -> None:
        _validate({}, {"requireTimestamps": False})

    def test_reject_missing_timestamps_when_required(self) -> None:
        with pytest.raises(APIError, match="SAML assertion missing required timestamp conditions"):
            _validate(None, {"requireTimestamps": True})

    def test_reject_empty_conditions_when_required(self) -> None:
        with pytest.raises(APIError, match="SAML assertion missing required timestamp conditions"):
            _validate({}, {"requireTimestamps": True})

    def test_accept_only_not_before_valid(self) -> None:
        now = _iso(_now())
        _validate({"notBefore": now})

    def test_accept_only_not_on_or_after_valid_future(self) -> None:
        future = _iso(_now() + timedelta(minutes=10))
        _validate({"notOnOrAfter": future})


# --------------------------------------------------------------------------- #
# Custom clock skew configuration
# --------------------------------------------------------------------------- #
class TestCustomClockSkewConfiguration:
    def test_use_custom_clock_skew_when_provided(self) -> None:
        two_seconds_ago = _iso(_now() - timedelta(seconds=2))
        with pytest.raises(APIError, match="SAML assertion has expired"):
            _validate({"notOnOrAfter": two_seconds_ago}, {"clockSkew": 1000})
        _validate({"notOnOrAfter": two_seconds_ago}, {"clockSkew": 5 * 60 * 1000})

    def test_use_default_5_minute_clock_skew_when_not_specified(self) -> None:
        four_minutes_ago = _iso(_now() - timedelta(minutes=4))
        _validate({"notOnOrAfter": four_minutes_ago})

        six_minutes_ago = _iso(_now() - timedelta(minutes=6))
        with pytest.raises(APIError, match="SAML assertion has expired"):
            _validate({"notOnOrAfter": six_minutes_ago})


# --------------------------------------------------------------------------- #
# Malformed timestamp handling
# --------------------------------------------------------------------------- #
class TestMalformedTimestampHandling:
    def test_reject_malformed_not_before(self) -> None:
        with pytest.raises(APIError, match="SAML assertion has invalid NotBefore timestamp"):
            _validate({"notBefore": "not-a-valid-date"})

    def test_reject_malformed_not_on_or_after(self) -> None:
        with pytest.raises(APIError, match="SAML assertion has invalid NotOnOrAfter timestamp"):
            _validate({"notOnOrAfter": "invalid-timestamp"})

    def test_treat_empty_string_timestamps_as_missing(self) -> None:
        _validate({"notBefore": ""})
        _validate({"notOnOrAfter": ""})

    def test_reject_garbage_data_in_timestamps(self) -> None:
        with pytest.raises(APIError, match="SAML assertion has invalid NotBefore timestamp"):
            _validate({"notBefore": "abc123xyz", "notOnOrAfter": "!@#$%^&*()"})

    def test_accept_valid_iso_8601_timestamps(self) -> None:
        now = _iso(_now())
        future = _iso(_now() + timedelta(minutes=10))
        _validate({"notBefore": now, "notOnOrAfter": future})
