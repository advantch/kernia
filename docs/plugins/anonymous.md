# Anonymous

> Module: `kernia.plugins.anonymous`
> Constructor: `anonymous`

anonymous plugin — port of `Better Auth reference: plugins/anonymous/`.

Provides ephemeral, account-less sign-in for first-time visitors. Hooks into the
email-password and magic-link sign-in/sign-up flows so that when an anonymous user
later "graduates" to a real account, the anonymous user row is collapsed into the
new user (via an optional `on_link` callback) and then deleted.

## Endpoints

| Method | Path |
| --- | --- |
| `POST` | `/sign-in/anonymous` |

## Schema contributions


**Extends existing tables:**

- `user` adds: isAnonymous

## Usage

```python
from kernia.plugins.anonymous import anonymous
from kernia import KerniaOptions
from kernia.auth import init

auth = init(
    KerniaOptions(
        database=...,
        secret=...,
        plugins=[
            anonymous(),
        ],
    )
)
```
