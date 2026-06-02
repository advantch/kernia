# Cookie & Session Model Specification

Source files:

- `reference/packages/better-auth/src/cookies/index.ts` —
  `createCookieGetter`, `getCookies`, `setSessionCookie`,
  `deleteSessionCookie`, `setCookieCache`, `getCookieCache`,
  `getSessionCookie`, `parseCookies`.
- `reference/packages/better-auth/src/cookies/cookie-utils.ts` —
  `parseSetCookieHeader`, `splitSetCookieHeader`,
  `SECURE_COOKIE_PREFIX`, `HOST_COOKIE_PREFIX`, `stripSecureCookiePrefix`.
- `reference/packages/better-auth/src/cookies/session-store.ts` —
  cookie chunking (>4KB), account-cookie helpers, `getChunkedCookie`,
  `getSessionQuerySchema`.
- `reference/packages/better-auth/src/crypto/jwt.ts` — `signJWT`,
  `verifyJWT`, `symmetricEncodeJWT`, `symmetricDecodeJWT`.
- `reference/packages/core/src/types/cookie.ts` — `KerniaCookie`,
  `KerniaCookies`.

## Cookie inventory

`getCookies(options)` returns four named cookies. The "logical name" is
what's used inside the auth context (`ctx.context.authCookies.*`); the
"on-the-wire name" is what shows up in the `Set-Cookie` / `Cookie`
header.

| Logical            | Wire (default)                  | Default `maxAge`                              |
| ------------------ | ------------------------------- | --------------------------------------------- |
| `sessionToken`     | `better-auth.session_token`     | `options.session.expiresIn` (`sec("7d")`)     |
| `sessionData`      | `better-auth.session_data`      | `options.session.cookieCache.maxAge` (300s)   |
| `dontRememberToken`| `better-auth.dont_remember`     | none — session cookie                         |
| `accountData`      | `better-auth.account_data`      | `options.session.cookieCache.maxAge` (300s)   |

### Prefixing

When `secure` is `true`, every cookie name is prefixed with
`__Secure-`. The "secure" decision (`createCookieGetter`):

1. `options.advanced.useSecureCookies` (explicit override) wins.
2. `options.baseURL` is an object with `protocol: "https"` → secure;
   `"http"` → not secure.
3. Static `baseURL` string starts with `https://` → secure.
4. Fallback: `isProduction` (i.e. `NODE_ENV === "production"`).

### Naming customization

- `options.advanced.cookiePrefix` (default `"better-auth"`) is the
  segment before the dot.
- `options.advanced.cookies.<logical>.name` overrides the wire name
  (still prefixed with `__Secure-` if secure).
- `options.advanced.cookies.<logical>.attributes` overrides per-cookie
  attributes.
- `options.advanced.defaultCookieAttributes` is merged into every cookie.

### Default attributes

```ts
{
  secure: !!secureCookiePrefix,
  sameSite: "lax",
  path: "/",
  httpOnly: true,
  // when crossSubDomainCookies.enabled:
  domain: options.advanced.crossSubDomainCookies.domain
          ?? new URL(baseURL).hostname,
  ...options.advanced.defaultCookieAttributes,
  ...overrideAttributes,
  ...options.advanced.cookies[name]?.attributes,
}
```

If `crossSubDomainCookies.enabled` is true but no `domain` can be
determined (and `baseURL` is not a dynamic config), `createCookieGetter`
throws `KerniaError("baseURL is required when crossSubdomainCookies are enabled.")`.

## Signing scheme

Better-Auth uses three cookie encodings; the choice depends on the
cookie:

### 1. Signed cookies (used for `sessionToken` and `dontRememberToken`)

`ctx.setSignedCookie(name, value, secret, options)` and
`ctx.getSignedCookie(name, secret)` come from `better-call`. The on-the-wire
format is the value followed by a `.`-separator and an HMAC-SHA256
signature of `name=value`, base64url-encoded. Verification is a constant-time
HMAC compare. The signing key is `ctx.context.secret`.

This is opaque to the user: only `value` (the session token, an
opaque random string from `internalAdapter.createSession`) is observable
to the server after parsing.

### 2. Cookie-cache (`sessionData`) — three strategies

`options.session.cookieCache.strategy` selects:

- `"compact"` (**default**, also covers legacy `"base64-hmac"`):
  ```
  base64url( JSON.stringify({
    session: { session, user, updatedAt, version },
    expiresAt,                                        // unix ms
    signature: HMAC_SHA256_base64urlnopad(secret, {…sessionData, expiresAt})
  }) )
  ```
  Verification rebuilds the same JSON and HMAC-verifies the signature.

- `"jwt"`: `signJWT(payload, secret, maxAge)` (HS256). Payload is
  `{ session, user, updatedAt, version, exp }`. `verifyJWT` is used on
  read.

- `"jwe"`: `symmetricEncodeJWT(payload, secretConfig, audience: "better-auth-session", maxAge)`.
  AES-256-CBC + HMAC-SHA-512 with keys derived via HKDF. `secretConfig`
  is the rotating-secret config (`core/types/secret.ts`), so primary +
  rotated secrets are all tried on decode.

### 3. Account-cache (`accountData`)

Always JWE-encrypted with `symmetricEncodeJWT(accountData, secretConfig, "better-auth-account", maxAge)`.
Holds the user's OAuth account record (access token, refresh token,
etc.) for fast retrieval by `/get-access-token`.

## `getSessionQuerySchema` (session route query params)

`reference/packages/better-auth/src/cookies/session-store.ts` exports
the Zod schema:

```ts
export const getSessionQuerySchema = z.object({
  disableCookieCache: z.coerce.boolean().optional(),
  disableRefresh: z.coerce.boolean().optional(),
});
```

## Session-token shape

The session row (from `core/src/db/schema/session.ts`):

```
Session = {
  id: string;
  token: string;            // opaque; what lives inside the signed cookie
  userId: string;
  expiresAt: Date;
  createdAt: Date;
  updatedAt: Date;
  ipAddress?: string;
  userAgent?: string;
  impersonatedBy?: string;  // admin-impersonation plugin
}
```

`token` is generated by `internalAdapter.createSession` and is what's
stored as the value of the signed `session_token` cookie. The cookie
signature wraps that token; the token itself is opaque (no embedded JWT).
DB lookup is `internalAdapter.findSession(token)` keyed on `token`.

## Cookie-cache payload

`setCookieCache(ctx, session, dontRememberMe)` builds:

```ts
{
  session: filterOutputFields(session.session, options.session.additionalFields),
  user: parseUserOutput(options, session.user),
  updatedAt: Date.now(),
  version: <string>,    // from options.session.cookieCache.version
                        // (defaults to "1"; can be a function of session+user)
}
```

If the encoded blob exceeds 4096 - 200 = 3896 bytes, it's chunked into
`name.0`, `name.1`, …, `name.N` cookies of size 3896. `getSessionStore`
in `session-store.ts` handles chunk write + clean-up.

Version mismatch (cookie has `version !== expectedVersion`) invalidates
the cache; a fresh DB read is used and the cookie is overwritten.

`get-session` honors `cookieRefreshCache.updateAge` to decide whether
to refresh the cache on read.

## `dontRememberToken`

Set when the user signs in with `rememberMe === false`. Its presence
tells subsequent `setSessionCookie` calls to omit `maxAge` (making the
session token a session cookie that dies on browser close). The token's
own value is the literal string `"true"`, signed with the secret.

`get-session` reads it via `ctx.getSignedCookie(...)` and uses the
boolean only:

```ts
const dontRememberMe = await ctx.getSignedCookie(name, secret);
if (dontRememberMe || ctx.query?.disableRefresh) {
  // skip session refresh
}
```

`deleteSessionCookie(ctx, skipDontRememberMe?)` clears it too, unless
`skipDontRememberMe === true`.

## `setSessionCookie` flow (verbatim summary)

```ts
const dontRememberMeCookie =
  await ctx.getSignedCookie(dontRememberToken.name, secret);
dontRememberMe = dontRememberMe ?? !!dontRememberMeCookie;

const maxAge = dontRememberMe ? undefined : sessionConfig.expiresIn;
await ctx.setSignedCookie(
  sessionToken.name, session.session.token, secret,
  { ...sessionToken.attributes, maxAge, ...overrides }
);
if (dontRememberMe) {
  await ctx.setSignedCookie(
    dontRememberToken.name, "true", secret, dontRememberToken.attributes
  );
}
await setCookieCache(ctx, session, dontRememberMe);
ctx.context.setNewSession(session);
```

## `deleteSessionCookie` flow

Expires (with `maxAge: 0`):
- `sessionToken`
- `sessionData` (and all chunks)
- `accountData` (and chunks) when `options.account.storeAccountCookie`
- OAuth state cookie when `oauthConfig.storeStateStrategy === "cookie"`
- `dontRememberToken` (unless `skipDontRememberMe`)

Chunked cookies are walked via `createSessionStore(...).clean()` and
`createAccountStore(...).clean()`.

## Public reader: `getSessionCookie`

`getSessionCookie(request, { cookiePrefix?, cookieName? }?)` parses the
request `Cookie` header and returns the *raw cookie value* (still
signature-encoded). Useful for middlewares that only need to know
"is there a session?". It tries both `prefix.cookieName` and
`prefix-cookieName` (legacy hyphen form).

## Public reader: `getCookieCache`

`getCookieCache(request, { cookiePrefix?, cookieName?, isSecure?, secret?, strategy?, version? })`
parses, verifies, and returns the decoded session-data payload without
needing a full auth instance. Each strategy is decoded as documented
above. Requires `secret` (or `BETTER_AUTH_SECRET` env var).

## Secondary storage interface

```ts
export interface SecondaryStorage {
  /** key -> value (any JSON-serializable; some impls store strings only). */
  get: (key: string) => Awaitable<unknown>;

  /**
   * Optional atomic get-and-delete primitive.
   * Single-use credential consumers prefer this when present so they
   * avoid a read-then-delete race. Backward-compatible-optional today;
   * planned to become required.
   */
  getAndDelete?: (key: string) => Awaitable<unknown>;

  set: (key: string, value: string, ttl?: number) => Awaitable<void | null | unknown>;
  delete: (key: string) => Awaitable<void | null | string>;
}
```

Used by:

- Session storage when `options.session.storeSessionInDatabase === false`
  and `options.secondaryStorage` is provided. Sessions are written/read
  under `key = sessionToken` with `ttl = sessionConfig.expiresIn`.
- Verification storage when configured (e.g. one-time tokens, OAuth
  state when `storeStateStrategy === "secondary-storage"`).
- Rate limiting when `options.rateLimit.storage === "secondary-storage"`.

The Python port must preserve this exact tri-method interface (plus the
optional `getAndDelete`) so that Redis/Memcached/etc. plugins remain
drop-in.

## Cookie utilities for tests / middleware

- `parseCookies(cookieHeader)` → `Map<name, value>`.
- `parseSetCookieHeader(setCookie)` → `Map<name, CookieAttributes>`.
- `splitSetCookieHeader(setCookie)` → `string[]` (RFC-aware split — many
  runtimes collapse multiple `Set-Cookie` into one comma-joined header).
- `setRequestCookie(headers, name, value)` — mutate the request
  `Cookie` header in place (used by the bearer plugin).
- `stripSecureCookiePrefix(cookieName)` — drop `__Secure-` or `__Host-`.

## Python port notes

- Cookie helpers should sit on the context object (`ctx.set_cookie`,
  `ctx.set_signed_cookie`, …) as in the JS surface.
- Signing: HMAC-SHA256 over `name=value`, base64url-encoded (or use the
  same format better-call uses — `value.signature` separated by `.`).
- For the JWE strategy, prefer a battle-tested JOSE library (`jwcrypto`
  or `joserfc`) configured for `A256CBC-HS512` with HKDF-derived keys
  matching `symmetricEncodeJWT` (`reference/packages/better-auth/src/crypto/jwt.ts`).
- Cookie chunk size must remain `4096 - 200 = 3896` bytes to stay
  binary-compatible.
- Default cookie names MUST match the table above exactly.
