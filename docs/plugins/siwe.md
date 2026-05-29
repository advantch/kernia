# Siwe

> Module: `better_auth.plugins.siwe`
> Constructor: `ENSLookup`

siwe plugin — Sign-In With Ethereum.

Port of `reference/packages/better-auth/src/plugins/siwe/`. Issues a chain-scoped
nonce, verifies an EIP-4361 message + signature (via the pluggable
``verify_message`` option), consumes the nonce, then signs the user in
(auto-creating the user + a ``walletAddress`` record if needed).

Message verification is pluggable like upstream (``get_nonce`` / ``verify_message``).
The defaults use the optional ``eth-account`` dependency for real signature
recovery and a 17-char alphanumeric nonce. For ENS reverse-lookup, pass either an
``ens_lookup`` callback (upstream shape: ``{walletAddress} -> {name, avatar}``) or
the legacy ``ens_resolver`` / ``ens_rpc_url`` with ``enable_ens=True``.

## Endpoints

_(no HTTP endpoints — this plugin contributes hooks/schema only)_

## Schema contributions

_(no schema contributions)_

## Usage

```python
from better_auth.plugins.siwe import ENSLookup
from better_auth import BetterAuthOptions
from better_auth.auth import init

auth = init(
    BetterAuthOptions(
        database=...,
        secret=...,
        plugins=[
            ENSLookup(),
        ],
    )
)
```
