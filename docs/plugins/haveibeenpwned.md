# Haveibeenpwned

> Module: `kernia.plugins.haveibeenpwned`
> Constructor: `have_i_been_pwned`

Have-I-Been-Pwned password compromise plugin.

Mirrors `Better Auth reference: plugins/haveibeenpwned/index.ts`.
Hashes the candidate password (SHA-1), sends the first 5 hex chars to the
pwnedpasswords range API, and rejects the request if the remainder appears in
the response.

## Endpoints

_(no HTTP endpoints — this plugin contributes hooks/schema only)_

## Schema contributions

_(no schema contributions)_

## Usage

```python
from kernia.plugins.haveibeenpwned import have_i_been_pwned
from kernia import KerniaOptions
from kernia.auth import init

auth = init(
    KerniaOptions(
        database=...,
        secret=...,
        plugins=[
            have_i_been_pwned(),
        ],
    )
)
```
