# Siwe

> Module: `kernia.plugins.siwe`
> Constructor: `SIWE_ERROR_CODES`

siwe plugin — Sign-In With Ethereum.

Port of `reference/packages/better-auth/src/plugins/siwe/`. Verifies an
EIP-4361 message + signature, consumes a server-issued nonce, then signs the
user in (auto-creating the user with `walletAddress` if needed).

Requires the optional `eth-account` dependency (declared via the
`[project.optional-dependencies] siwe` extra on `kernia`).

## Endpoints

_(no HTTP endpoints — this plugin contributes hooks/schema only)_

## Schema contributions

_(no schema contributions)_

## Usage

```python
from kernia.plugins.siwe import SIWE_ERROR_CODES
from kernia import KerniaOptions
from kernia.auth import init

auth = init(
    KerniaOptions(
        database=...,
        secret=...,
        plugins=[
            SIWE_ERROR_CODES(),
        ],
    )
)
```
