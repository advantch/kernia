# Username

> Module: `kernia.plugins.username`
> Constructor: `USERNAME_ERROR_CODES`

username plugin — port of `reference/packages/better-auth/src/plugins/username/`.

Adds username-based sign-up/sign-in alongside the email/password credential rows.
The username column is stored in normalized (lower-case) form; `displayUsername`
preserves the originally-supplied casing.

## Endpoints

_(no HTTP endpoints — this plugin contributes hooks/schema only)_

## Schema contributions

_(no schema contributions)_

## Usage

```python
from kernia.plugins.username import USERNAME_ERROR_CODES
from kernia import KerniaOptions
from kernia.auth import init

auth = init(
    KerniaOptions(
        database=...,
        secret=...,
        plugins=[
            USERNAME_ERROR_CODES(),
        ],
    )
)
```
