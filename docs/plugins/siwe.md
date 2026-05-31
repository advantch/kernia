# Siwe

> Module: `kernia.plugins.siwe`
> Constructor: `siwe`

siwe plugin — Sign-In With Ethereum.

Port of `Better Auth reference: plugins/siwe/`. Verifies an
EIP-4361 message + signature, consumes a server-issued nonce, then signs the
user in (auto-creating the user with `walletAddress` if needed).

Requires the optional `eth-account` dependency. For ENS reverse-lookup, pass an
`ENSResolver` (e.g. `web3_ens_resolver(rpc_url=...)`) — without one, ENS lookup
is disabled even if `enable_ens=True`.

## Endpoints

| Method | Path |
| --- | --- |
| `GET` | `/siwe/nonce` |
| `POST` | `/siwe/verify` |

## Schema contributions


**Extends existing tables:**

- `user` adds: walletAddress, ensName

## Usage

```python
from kernia.plugins.siwe import siwe
from kernia import KerniaOptions
from kernia.auth import init

auth = init(
    KerniaOptions(
        database=...,
        secret=...,
        plugins=[
            siwe(),
        ],
    )
)
```
