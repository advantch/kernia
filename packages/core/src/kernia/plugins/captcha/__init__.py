"""Captcha plugin.

Mirrors `reference/packages/better-auth/src/plugins/captcha/`. The plugin
validates a captcha challenge token (carried in the `x-captcha-token` or legacy
`x-captcha-response` header) before sensitive endpoints run their handlers.

Built-in providers post to the public siteverify URL using httpx; each provider
is a `CaptchaProvider` instance with an async `.verify(token, ip) -> VerifyResult`.
Custom providers may be supplied directly.
"""

from kernia.plugins.captcha.plugin import captcha
from kernia.plugins.captcha.providers import (
    CaptchaProvider,
    VerifyResult,
    captchafox,
    hcaptcha,
    recaptcha_v2,
    recaptcha_v3,
    turnstile,
)

__all__ = [
    "CaptchaProvider",
    "VerifyResult",
    "captcha",
    "captchafox",
    "hcaptcha",
    "recaptcha_v2",
    "recaptcha_v3",
    "turnstile",
]
