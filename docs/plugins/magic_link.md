# Magic Link

> Module: `kernia.plugins.magic_link`
> Constructor: `magic_link`

magic_link — see Better Auth reference: plugins/magic-link/.

Passwordless sign-in via emailed short-lived URLs. Tokens are persisted in the
core `verification` table with identifier `magic-link:<token>` and atomically
consumed on first GET to `/magic-link/verify`.

## Endpoints

| Method | Path |
| --- | --- |
| `POST` | `/sign-in/magic-link` |
| `GET` | `/magic-link/verify` |

## Schema contributions

_(no schema contributions)_

## Usage

```python
from kernia.plugins.magic_link import magic_link
from kernia import KerniaOptions
from kernia.auth import init

auth = init(
    KerniaOptions(
        database=...,
        secret=...,
        plugins=[
            magic_link(),
        ],
    )
)
```
