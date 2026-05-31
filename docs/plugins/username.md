# Username

> Module: `kernia.plugins.username`
> Constructor: `username`

username plugin — port of `Better Auth reference: plugins/username/`.

Adds username-based sign-up/sign-in alongside the email/password credential rows.
The username column is stored in normalized (lower-case) form; `displayUsername`
preserves the originally-supplied casing.

## Endpoints

| Method | Path |
| --- | --- |
| `POST` | `/sign-up/username` |
| `POST` | `/sign-in/username` |

## Schema contributions


**Extends existing tables:**

- `user` adds: username, displayUsername

## Usage

```python
from kernia.plugins.username import username
from kernia import KerniaOptions
from kernia.auth import init

auth = init(
    KerniaOptions(
        database=...,
        secret=...,
        plugins=[
            username(),
        ],
    )
)
```
