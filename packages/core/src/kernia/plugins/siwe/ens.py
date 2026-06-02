"""ENS reverse-lookup helpers for the SIWE plugin.

Public API:
    `ENSResolver` — protocol for an async `(address: str) -> str | None`.
    `web3_ens_resolver(rpc_url, timeout=5.0)` — returns a resolver backed by web3.py.

The default resolver hits an Ethereum JSON-RPC endpoint. Users supply the URL
(Alchemy / Infura / a self-hosted node); we don't ship a default URL because
mainnet RPC is not free and the choice of provider belongs to the user.

If a lookup raises or times out, the resolver returns `None` — sign-in must
never fail because ENS is unreachable.
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable

ENSResolver = Callable[[str], Awaitable[str | None]]


def web3_ens_resolver(
    rpc_url: str,
    *,
    timeout: float = 5.0,
) -> ENSResolver:
    """Build a resolver backed by `web3.py` over the supplied HTTP(S) RPC URL.

    Lazy-imports `web3` so the dependency stays optional. Raises ImportError on
    first use if `web3` isn't installed; callers can fall back to passing a
    custom resolver instead.
    """

    async def _resolve(address: str) -> str | None:
        try:
            from web3 import Web3
            from web3.providers.rpc import HTTPProvider
        except ImportError as exc:  # pragma: no cover — env-dependent
            raise ImportError(
                "web3.py is required for the default ENS resolver. "
                "Install with `pip install 'web3>=6'` or supply a custom resolver."
            ) from exc

        # web3.py is sync; off-thread it. Cap with timeout so we don't block sign-in.
        def _sync_lookup() -> str | None:
            w3 = Web3(HTTPProvider(rpc_url, request_kwargs={"timeout": timeout}))
            try:
                name = w3.ens.name(address)  # type: ignore[union-attr]
            except Exception:
                return None
            if not name:
                return None
            # Forward-resolve as confirmation: an ENS name's "name" record must
            # resolve back to the same address. Without this check we'd accept
            # squatted reverse records.
            try:
                forward = w3.ens.address(name)  # type: ignore[union-attr]
            except Exception:
                return None
            if forward is None or forward.lower() != address.lower():
                return None
            return name

        try:
            return await asyncio.wait_for(asyncio.to_thread(_sync_lookup), timeout=timeout)
        except (TimeoutError, Exception):
            return None

    return _resolve


__all__ = ["ENSResolver", "web3_ens_resolver"]
