# Oidc Provider

> Module: `better_auth.plugins.oidc_provider`
> Constructor: `oidc_provider`

Deprecated shim for the standalone OAuth2.1 / OIDC provider.

Mirrors better-auth upstream, where the in-tree ``oidc-provider`` plugin is
**deprecated** in favour of the dedicated ``@better-auth/oauth-provider`` package
(the full OAuth 2.1 + OpenID Connect issuer: PKCE, refresh rotation with reuse
detection, RFC 7662 introspection, RFC 7009 revocation, RFC 8414 metadata,
dynamic client registration, …).

The Python port follows the same split: the real implementation lives in the
``better_auth_oauth_provider`` package. This module remains importable so legacy
call sites keep working, but every entry point emits a :class:`DeprecationWarning`
and delegates to ``better_auth_oauth_provider``.

Migration::

    # before (deprecated)
    from better_auth.plugins.oidc_provider import oidc_provider

    # after
    from better_auth_oauth_provider import oauth_provider, OAuthProviderOptions

Importing this shim does *not* pull in the provider package; the delegation is
lazy so core has no hard dependency on the standalone package.

## Endpoints

_(no HTTP endpoints — this plugin contributes hooks/schema only)_

## Schema contributions

_(no schema contributions)_

## Usage

```python
from better_auth.plugins.oidc_provider import oidc_provider
from better_auth import BetterAuthOptions
from better_auth.auth import init

auth = init(
    BetterAuthOptions(
        database=...,
        secret=...,
        plugins=[
            oidc_provider(),
        ],
    )
)
```
