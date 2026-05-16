# Haveibeenpwned

> Module: `better_auth.plugins.haveibeenpwned`
> Constructor: `have_i_been_pwned`

Have-I-Been-Pwned password compromise plugin.

Mirrors `reference/packages/better-auth/src/plugins/haveibeenpwned/index.ts`.
Hashes the candidate password (SHA-1), sends the first 5 hex chars to the
pwnedpasswords range API, and rejects the request if the remainder appears in
the response.

## Endpoints

_(no HTTP endpoints — this plugin contributes hooks/schema only)_

## Schema contributions

_(no schema contributions)_

## Usage

```python
from better_auth.plugins.haveibeenpwned import have_i_been_pwned
from better_auth import BetterAuthOptions
from better_auth.auth import init

auth = init(
    BetterAuthOptions(
        database=...,
        secret=...,
        plugins=[
            have_i_been_pwned(),
        ],
    )
)
```
