# Siwe

> Module: `better_auth.plugins.siwe`
> Constructor: `ENSResolver`

siwe plugin — Sign-In With Ethereum.

Port of `reference/packages/better-auth/src/plugins/siwe/`. Verifies an
EIP-4361 message + signature, consumes a server-issued nonce, then signs the
user in (auto-creating the user with `walletAddress` if needed).

Requires the optional `eth-account` dependency. For ENS reverse-lookup, pass an
`ENSResolver` (e.g. `web3_ens_resolver(rpc_url=...)`) — without one, ENS lookup
is disabled even if `enable_ens=True`.

## Endpoints

_(no HTTP endpoints — this plugin contributes hooks/schema only)_

## Schema contributions

_(no schema contributions)_

## Usage

```python
from better_auth.plugins.siwe import ENSResolver
from better_auth import BetterAuthOptions
from better_auth.auth import init

auth = init(
    BetterAuthOptions(
        database=...,
        secret=...,
        plugins=[
            ENSResolver(),
        ],
    )
)
```
