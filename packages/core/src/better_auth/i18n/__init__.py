"""i18n — translate error responses based on detected locale.

Mirrors `reference/packages/i18n/`. Ported as a plugin you opt into:

    from better_auth.i18n import i18n
    init(BetterAuthOptions(..., plugins=[
        i18n(
            translations={
                "en": {"USER_NOT_FOUND": "User not found"},
                "fr": {"USER_NOT_FOUND": "Utilisateur non trouvé"},
                "de": {"USER_NOT_FOUND": "Benutzer nicht gefunden"},
            },
            default_locale="en",
            detection=("header", "cookie"),
        ),
    ]))

Detection strategies (in order):
  - "header"  — `Accept-Language` (q-sorted, base locale; "en-US" → "en")
  - "cookie"  — the `locale_cookie` cookie value
  - "user"    — `user.<user_locale_field>` if a session is attached

The plugin hooks the response pipeline: when an APIError envelope is being
serialized, if the error's `code` has a translation for the detected locale,
the `message` field is replaced.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Literal

DetectionStrategy = Literal["header", "cookie", "user"]


def parse_accept_language(header: str | None) -> list[str]:
    """Return base locales (e.g. 'en' from 'en-US') sorted by q-value descending."""
    if not header:
        return []
    parts: list[tuple[str, float]] = []
    for chunk in header.split(","):
        loc, _, q = chunk.strip().partition(";")
        q_val = 1.0
        if q.startswith("q="):
            try:
                q_val = float(q[2:])
            except ValueError:
                q_val = 1.0
        base = loc.strip().split("-")[0]
        if base:
            parts.append((base, q_val))
    parts.sort(key=lambda p: -p[1])
    return [p[0] for p in parts]


@dataclass(frozen=True, slots=True)
class _I18nPlugin:
    id: str = "i18n"
    version: str | None = None
    translations: Mapping[str, Mapping[str, str]] = field(default_factory=dict)
    default_locale: str = "en"
    detection: tuple[DetectionStrategy, ...] = ("header",)
    locale_cookie: str = "locale"
    user_locale_field: str = "locale"
    # plugin protocol fields:
    schema: None = None
    endpoints: None = None
    middlewares: None = None
    hooks: None = None
    on_request: None = None
    rate_limit: None = None
    error_codes: None = None
    init: None = None

    async def on_response(self, ctx, result):  # type: ignore[no-untyped-def]
        # Translate APIError-shaped dicts: {"code": "...", "message": "..."}.
        # The result is plain JSON; we only mutate when the shape matches.
        if not isinstance(result, dict):
            return None
        code = result.get("code")
        if not isinstance(code, str):
            return None
        locale = self._detect(ctx)
        translated = self.translations.get(locale, {}).get(code)
        if translated is None and locale != self.default_locale:
            translated = self.translations.get(self.default_locale, {}).get(code)
        if translated is not None:
            result["message"] = translated
        return None

    def _detect(self, ctx) -> str:  # type: ignore[no-untyped-def]
        for strategy in self.detection:
            if strategy == "header":
                for loc in parse_accept_language(ctx.request.headers.get("accept-language")):
                    if loc in self.translations:
                        return loc
            elif strategy == "cookie":
                cookie_val = ctx.request.cookies.get(self.locale_cookie)
                if cookie_val and cookie_val in self.translations:
                    return cookie_val
            elif strategy == "user":
                if ctx.user is not None:
                    user_locale = getattr(ctx.user, self.user_locale_field, None)
                    if isinstance(user_locale, str) and user_locale in self.translations:
                        return user_locale
        return self.default_locale


def i18n(
    *,
    translations: Mapping[str, Mapping[str, str]],
    default_locale: str = "en",
    detection: Sequence[DetectionStrategy] = ("header",),
    locale_cookie: str = "locale",
    user_locale_field: str = "locale",
):
    """Construct the i18n plugin. See module docstring for usage."""
    if not translations:
        raise ValueError("i18n: at least one locale must be supplied")
    if default_locale not in translations:
        # better-auth falls back to "en" if present, else first available.
        if "en" in translations:
            default_locale = "en"
        else:
            default_locale = next(iter(translations))
    return _I18nPlugin(
        translations=dict(translations),
        default_locale=default_locale,
        detection=tuple(detection),
        locale_cookie=locale_cookie,
        user_locale_field=user_locale_field,
    )


__all__ = ["i18n", "parse_accept_language"]
