# Captcha

> Module: `kernia.plugins.captcha`
> Constructor: `captcha`

Captcha plugin.

Mirrors `Better Auth reference: plugins/captcha/`. The plugin
validates a captcha challenge token (carried in the `x-captcha-token` or legacy
`x-captcha-response` header) before sensitive endpoints run their handlers.

Built-in providers post to the public siteverify URL using httpx; each provider
is a `CaptchaProvider` instance with an async `.verify(token, ip) -> VerifyResult`.
Custom providers may be supplied directly.

## Endpoints

_(no HTTP endpoints — this plugin contributes hooks/schema only)_

## Schema contributions

_(no schema contributions)_

## Usage

```python
from kernia.plugins.captcha import captcha
from kernia import KerniaOptions
from kernia.auth import init

auth = init(
    KerniaOptions(
        database=...,
        secret=...,
        plugins=[
            captcha(),
        ],
    )
)
```
