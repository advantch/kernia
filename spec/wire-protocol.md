# Wire Protocol Specification

This document describes every public auth route exposed by Better Auth core
(`reference/packages/better-auth/src/api/routes/`). All routes are registered
on a base path (default `/api/auth`) and aggregated via
`reference/packages/better-auth/src/api/routes/index.ts`.

Notation:
- **Body** / **Query** shapes are quoted from the route's Zod schema verbatim.
- **Response** shapes are quoted from the route's `metadata.$Infer.returned`
  when present, otherwise from `metadata.openapi`.
- **Set-Cookie** column lists the cookies the route writes/deletes.
- Errors are thrown with `APIError.from(httpStatus, BASE_ERROR_CODES.<code>)`;
  see `reference/packages/core/src/error/codes.ts` for the complete map.
- Origin / CSRF middleware: see `reference/packages/better-auth/src/api/middlewares/origin-check.ts`.
- Cookie names (default `better-auth.<key>`) and signing are documented in
  `cookie-session-model.md`.

---

## Cookie name reference

From `reference/packages/better-auth/src/cookies/index.ts::getCookies`:

| Logical name        | Default cookie name              | Purpose                                |
| ------------------- | -------------------------------- | -------------------------------------- |
| `sessionToken`      | `better-auth.session_token`      | Signed HMAC; holds opaque session id   |
| `sessionData`       | `better-auth.session_data`       | Cookie-cache of `{session,user}`       |
| `dontRememberToken` | `better-auth.dont_remember`      | Signed; suppresses session refresh     |
| `accountData`       | `better-auth.account_data`       | Cookie-cache of linked account tokens  |

All cookies are prefixed with `__Secure-` when `secure` is true (production /
HTTPS baseURL). Default attributes:
`{ httpOnly: true, sameSite: "lax", path: "/", secure }`.

---

## /sign-up/email

File: `reference/packages/better-auth/src/api/routes/sign-up.ts`

- **Method:** `POST`
- **operationId:** `signUpWithEmailAndPassword`
- **Middlewares:** `formCsrfMiddleware`
- **Allowed media types:** `application/x-www-form-urlencoded`, `application/json`
- **Body** (`$Infer.body`):
  ```ts
  {
    name: string;
    email: string;
    password: string;
    image?: string | undefined;
    callbackURL?: string | undefined;
    rememberMe?: boolean | undefined;
  } & AdditionalUserFieldsInput<O>
  ```
- **Response 200** (`$Infer.returned`):
  ```ts
  {
    token: string | null;       // null when sign-up requires email verification or autoSignIn=false
    user: User<O["user"], O["plugins"]>;
  }
  ```
- **Set-Cookie:** writes `session_token` (signed), and `session_data` (cache)
  when a session is created; sets `dont_remember` when `rememberMe === false`.
- **Errors (status / code):**
  - `400 EMAIL_PASSWORD_SIGN_UP_DISABLED` — email/password disabled or `disableSignUp`.
  - `400 INVALID_EMAIL`
  - `400 INVALID_PASSWORD`
  - `400 PASSWORD_TOO_SHORT` / `PASSWORD_TOO_LONG`
  - `400 FAILED_TO_CREATE_USER`
  - `400 FAILED_TO_CREATE_SESSION`
  - `422 USER_ALREADY_EXISTS_USE_ANOTHER_EMAIL` (unless duplicate-response masking is active)
  - `422 FAILED_TO_CREATE_USER`

Notes (from `sign-up.ts`):
- Email is `.toLowerCase()`-normalized before adapter lookup/create.
- When `emailAndPassword.requireEmailVerification` or `autoSignIn === false`,
  the response masks duplicate accounts by returning a synthetic user with
  `token: null` (timing-safe; password is still hashed). See lines 234-313.
- Credential account is linked via `internalAdapter.linkAccount({ providerId: "credential", password: hash, ... })`.
- Verification email is sent if `emailVerification.sendOnSignUp` or
  `emailAndPassword.requireEmailVerification` is set; URL template:
  `${baseURL}/verify-email?token=<jwt>&callbackURL=<encoded>`.

---

## /sign-in/email

File: `reference/packages/better-auth/src/api/routes/sign-in.ts`

- **Method:** `POST`
- **Middlewares:** `formCsrfMiddleware`
- **Allowed media types:** form + JSON
- **Body:**
  ```ts
  {
    email: string;
    password: string;
    callbackURL?: string | undefined;
    rememberMe?: boolean | undefined; // default true
  }
  ```
- **Response 200:**
  ```ts
  {
    redirect: boolean;          // true when callbackURL is set (also sets Location header)
    token: string;
    url?: string | undefined;
    user: User<O["user"], O["plugins"]>;
  }
  ```
- **Set-Cookie:** `session_token`, optionally `session_data`, `dont_remember`.
- **Errors:**
  - `400 EMAIL_PASSWORD_DISABLED`
  - `400 INVALID_EMAIL`
  - `401 INVALID_EMAIL_OR_PASSWORD` (returned for missing user, missing credential account, missing password, or wrong password)
  - `403 EMAIL_NOT_VERIFIED` (when `emailAndPassword.requireEmailVerification` and not verified)
  - `401 FAILED_TO_CREATE_SESSION`

Timing-attack mitigation: `ctx.context.password.hash(password)` is invoked
even on lookup failure paths.

---

## /sign-in/social

File: `reference/packages/better-auth/src/api/routes/sign-in.ts` (lines 176-358).

- **Method:** `POST`
- **operationId:** `socialSignIn`
- **Body** (zod):
  ```ts
  {
    callbackURL?: string;
    newUserCallbackURL?: string;
    errorCallbackURL?: string;
    provider: SocialProvider;           // enum from `core/social-providers/index.ts`
    disableRedirect?: boolean;
    idToken?: {
      token: string;
      nonce?: string;
      accessToken?: string;
      refreshToken?: string;
      expiresAt?: number;
      user?: { name?: { firstName?: string; lastName?: string }; email?: string };
    };
    scopes?: string[];
    requestSignUp?: boolean;
    loginHint?: string;
    additionalData?: Record<string, any>;
  }
  ```
- **Response 200 (idToken branch — session immediately):**
  ```ts
  { redirect: false; token: string; url: undefined; user: User<...> }
  ```
- **Response 200 (redirect branch):**
  ```ts
  { redirect: boolean; url: string }
  ```
  Plus `Location: <provider authorize URL>` header when `disableRedirect` is falsy.
- **Set-Cookie (redirect branch):** OAuth state cookie (`__Secure-better-auth.state` or DB row depending on `oauthConfig.storeStateStrategy`); see `oauth2/state.ts`.
- **Set-Cookie (idToken branch):** `session_token`, `session_data`.
- **Errors:**
  - `404 PROVIDER_NOT_FOUND`
  - `404 ID_TOKEN_NOT_SUPPORTED`
  - `401 INVALID_TOKEN`
  - `401 FAILED_TO_GET_USER_INFO`
  - `401 USER_EMAIL_NOT_FOUND`
  - `401 OAUTH_LINK_ERROR` (when `handleOAuthUserInfo` returns `error`)

---

## /sign-out

File: `reference/packages/better-auth/src/api/routes/sign-out.ts`

- **Method:** `POST`
- **Headers:** required
- **Body / Query:** none
- **Response 200:** `{ success: boolean }`
- **Set-Cookie:** deletes `session_token`, `session_data` (incl. chunks),
  `account_data` (when `account.storeAccountCookie`), `dont_remember`,
  OAuth state cookie. See `cookies/index.ts::deleteSessionCookie`.
- Behavior: reads the signed session-token cookie, calls
  `internalAdapter.deleteSession(token)` (errors are logged, not surfaced).

---

## /get-session

File: `reference/packages/better-auth/src/api/routes/session.ts`

- **Method:** `GET` (also `POST` when `session.deferSessionRefresh` is enabled).
- **Query** (`getSessionQuerySchema` from `cookies/session-store.ts`):
  ```ts
  {
    disableCookieCache?: boolean;
    disableRefresh?: boolean;
  }
  ```
- **Response 200:**
  ```ts
  { session: Session<Option["session"], Option["plugins"]>;
    user: User<Option["user"], Option["plugins"]> } | null
  ```
  Also emits `needsRefresh` flag when `deferSessionRefresh` is enabled and the
  request is `GET` and session needs a write-side refresh (lines 430-449).
- **Set-Cookie:** May refresh `session_token` (sliding expiry), set or expire
  `session_data` based on `cookieCache` config and strategy
  (`compact`/`jwt`/`jwe`).
- **Errors:**
  - `405 METHOD_NOT_ALLOWED_DEFER_SESSION_REQUIRED` — POST without deferSessionRefresh.
  - `401 FAILED_TO_GET_SESSION`
  - `500 FAILED_TO_GET_SESSION`

Refresh semantics:
```
sessionIsDueToBeUpdated = expiresAt - expiresIn*1000 + updateAge*1000
shouldBeUpdated = sessionIsDueToBeUpdated <= now
```
Cookie-cache validation flow: HMAC verify (compact strategy), JWE decrypt
(`jwe`), JWT verify (`jwt`); version mismatch invalidates cache.

---

## /list-sessions

- **Method:** `GET`
- **Middlewares:** `sessionMiddleware` (auth required).
- **Response 200:** `Session<...>[]` — filtered to `expiresAt > now`.

## /revoke-session, /revoke-sessions, /revoke-other-sessions

- **Method:** `POST`
- **Middlewares:** `sensitiveSessionMiddleware` (no cookie-cache).
- `/revoke-session` body: `{ token: string }`.
- All return `{ status: true }`.

---

## /send-verification-email

File: `reference/packages/better-auth/src/api/routes/email-verification.ts`

- **Method:** `POST`
- **Body:**
  ```ts
  { email: string; callbackURL?: string }
  ```
- **Response 200:** `{ status: boolean }`
- **Errors:**
  - `400 VERIFICATION_EMAIL_NOT_ENABLED`
  - `400 EMAIL_MISMATCH` (signed-in user requesting different email)
  - `400 EMAIL_ALREADY_VERIFIED`
- Token: `signJWT({ email, updateTo? , ...extraPayload }, secret, expiresIn=3600)` — HS256 via `crypto/jwt.ts`.

## /verify-email

- **Method:** `GET`
- **Query:** `{ token: string; callbackURL?: string }`
- **Middlewares:** `originCheck(ctx => ctx.query.callbackURL)`
- **Response 200 (no redirect):** `{ status: true; user: User | null }`
- **Redirect:** to `callbackURL` on success (no query params added); on error
  appends `?error=<CODE>` to `callbackURL`.
- **Errors emitted via redirect:**
  - `TOKEN_EXPIRED`, `INVALID_TOKEN` (JWT verify failure)
  - `USER_NOT_FOUND`
  - `INVALID_USER` (session/user mismatch on change-email confirmation)
- **Branches** by `parsed.requestType`:
  - `change-email-confirmation` — sends `change-email-verification` token to new email.
  - `change-email-verification` — updates user.email to `updateTo`, sets `emailVerified: true`, sets session cookie.
  - default — legacy update path: updates email (sets `emailVerified: false`), re-sends verification.
  - When `updateTo` absent — sets `user.emailVerified = true`, optionally creates session if `autoSignInAfterVerification`.

---

## /request-password-reset

File: `reference/packages/better-auth/src/api/routes/password.ts`

- **Method:** `POST`
- **Middlewares:** `originCheck(ctx => ctx.body.redirectTo)`
- **Body:** `{ email: string; redirectTo?: string }`
- **Response 200:** `{ status: true; message: string }` — always (anti-enumeration).
- **Errors:** `400 RESET_PASSWORD_DISABLED` if `emailAndPassword.sendResetPassword` not configured.
- Verification stored as `internalAdapter.createVerificationValue({ identifier: "reset-password:<id>", value: user.id, expiresAt })`.
- Reset URL template: `${baseURL}/reset-password/<token>?callbackURL=<encoded>`.
- Default TTL: `60*60` seconds; overridable via `emailAndPassword.resetPasswordTokenExpiresIn`.

## /reset-password/:token (callback)

- **Method:** `GET`
- **Query:** `{ callbackURL: string }`
- **Middlewares:** `originCheck(ctx => ctx.query.callbackURL)`
- **Behavior:** Validates verification record exists and not expired;
  redirects to `callbackURL?token=<token>`. On failure redirects to
  `callbackURL?error=INVALID_TOKEN` (or `${baseURL}/error?error=INVALID_TOKEN`).

## /reset-password

- **Method:** `POST`
- **Query:** `{ token?: string }`
- **Body:** `{ newPassword: string; token?: string }` (token may come from body or query).
- **Response 200:** `{ status: true }`
- **Errors:** `400 INVALID_TOKEN`, `400 PASSWORD_TOO_SHORT`, `400 PASSWORD_TOO_LONG`.
- **Side effects:**
  - Creates a `credential` account if one does not exist, else `updatePassword`.
  - Calls `deleteVerificationByIdentifier` on the reset id.
  - Optionally invokes `emailAndPassword.onPasswordReset({ user }, request)`.
  - Optionally `revokeSessionsOnPasswordReset` -> `internalAdapter.deleteSessions(userId)`.

## /verify-password

- **Method:** `POST`
- **Middlewares:** `sensitiveSessionMiddleware`
- **Body:** `{ password: string }`
- **Response 200:** `{ status: true }`
- **Errors:** `400 INVALID_PASSWORD`

---

## /callback/:id (OAuth callback)

File: `reference/packages/better-auth/src/api/routes/callback.ts`

- **Method:** `GET` (POST is normalized to a redirect to GET to ensure cookies are sent).
- **Query / Body schema:**
  ```ts
  {
    code?: string;
    error?: string;
    device_id?: string;
    error_description?: string;
    state?: string;
    user?: string;     // JSON-encoded { name?: {firstName?, lastName?}; email? } for Apple
  }
  ```
- **Successful sign-in:** redirects to `callbackURL` (or `newUserURL` on first registration).
- **Set-Cookie:** `session_token`, `session_data` via `setSessionCookie`.
- **Failure:** redirects to `errorURL ?? options.onAPIError?.errorURL ?? ${baseURL}/error` with `?error=<reason>` query.
- **Failure reasons emitted as query string:**
  `invalid_callback_request`, `state_not_found`, `<provider error>`, `no_code`,
  `oauth_provider_not_found`, `invalid_code`, `unable_to_get_user_info`,
  `no_callback_url`, `unable_to_link_account`, `email_doesn't_match`,
  `account_already_linked_to_different_user`, `email_not_found`.

State is parsed via `parseState(c)` from `oauth2/state.ts`. The codeVerifier
(PKCE), `callbackURL`, `link` (link-account intent), `errorURL`, `newUserURL`,
and `requestSignUp` flag are recovered from cookie or DB depending on
`oauthConfig.storeStateStrategy`.

---

## /sign-in/social authorize URL generation (OAuth start)

OAuth start is the redirect branch of `/sign-in/social`. The provider's
`createAuthorizationURL({ state, codeVerifier, redirectURI, scopes, loginHint })`
yields the authorize URL. `redirectURI` is always
`${baseURL}/callback/${provider.id}`.

State generation (`utils/state.ts` / `oauth2/state.ts`) writes either:
- a signed encrypted cookie (`storeStateStrategy: "cookie"`), or
- a `verification` row (`storeStateStrategy: "database"`).

Payload includes `codeVerifier`, `callbackURL`, `errorURL`, `newUserURL`,
`requestSignUp`, and, for link-account flows, `{ userId, email }`.

---

## /link-social, /unlink-account, /list-accounts, /get-access-token, /refresh-token, /account-info

File: `reference/packages/better-auth/src/api/routes/account.ts`

- `/link-social` — `POST`, body matches `/sign-in/social` minus
  `disableRedirect`-only fields; uses `sessionMiddleware`. Returns either a
  redirect to the provider, or `{ url: "", status: true, redirect: false }` for
  the idToken branch.
- `/unlink-account` — `POST`, body `{ providerId; accountId? }`,
  `freshSessionMiddleware`. Errors: `400 FAILED_TO_UNLINK_LAST_ACCOUNT`,
  `400 ACCOUNT_NOT_FOUND`. Response: `{ status: true }`.
- `/list-accounts` — `GET`, `sessionMiddleware`. Response: array of accounts
  with `scopes: string[]`.
- `/get-access-token` — `POST`, body `{ providerId; accountId?; userId? }`.
  Returns `{ accessToken, accessTokenExpiresAt, scopes, idToken }`. Refreshes
  in-place if expired (within 5 seconds). Errors:
  `UNAUTHORIZED`, `400 PROVIDER_NOT_SUPPORTED`, `400 ACCOUNT_NOT_FOUND`,
  `400 FAILED_TO_GET_ACCESS_TOKEN`.
- `/refresh-token` — `POST`, body `{ providerId; accountId?; userId? }`.
  Errors: `400 TOKEN_REFRESH_NOT_SUPPORTED`, `400 REFRESH_TOKEN_NOT_FOUND`,
  `400 FAILED_TO_REFRESH_ACCESS_TOKEN`.
- `/account-info` — `GET`, query `{ accountId? }`, `sessionMiddleware`.
  Returns the provider's userinfo payload.

---

## /update-user, /change-password, /set-password, /delete-user, /delete-user/callback, /change-email

File: `reference/packages/better-auth/src/api/routes/update-user.ts`

- `/update-user` — `POST`, `sessionMiddleware`. Body is open-ended
  `Record<string, any>` infer-typed as
  `Partial<AdditionalUserFieldsInput<O>> & { name?; image? }`. Rejects body
  with `email` field (`400 EMAIL_CAN_NOT_BE_UPDATED`).
- `/change-password` — `POST`, `sessionMiddleware`. Body
  `{ currentPassword; newPassword; revokeOtherSessions? }`.
- `/set-password` — `POST` server-only. Body `{ newPassword }`. Errors:
  `400 PASSWORD_ALREADY_SET`.
- `/delete-user` — `POST`, `freshSessionMiddleware`. Body
  `{ password?; token?; callbackURL? }`.
- `/delete-user/callback` — `GET`, redirected via signed token.
- `/change-email` — `POST`, `sessionMiddleware`. Body
  `{ newEmail; callbackURL? }`. Triggers `change-email-confirmation` JWT flow.

---

## /update-session

File: `reference/packages/better-auth/src/api/routes/update-session.ts`

- **Method:** `POST`
- **Behavior:** Mutates session row's `updatedAt`/extension fields when defer
  refresh is enabled; used by client to push refresh manually.

---

## /ok

File: `reference/packages/better-auth/src/api/routes/ok.ts`

- **Method:** `GET`
- **Response 200:** `{ ok: true }`

## /error

File: `reference/packages/better-auth/src/api/routes/error.ts`

- **Method:** `GET`
- **Query:** `?error=<CODE>&error_description=<text>`
- **Response 200:** HTML error page; redirects to `options.onAPIError.errorURL`
  if configured.

---

## Origin / CSRF middleware

File: `reference/packages/better-auth/src/api/middlewares/origin-check.ts`

- `formCsrfMiddleware` — applied to form-submittable routes (`/sign-up/email`,
  `/sign-in/email`). Validates `Origin` header against `trustedOrigins`.
  Errors: `403 CROSS_SITE_NAVIGATION_LOGIN_BLOCKED`, `403 MISSING_OR_NULL_ORIGIN`.
- `originCheck(getURL)` — validates a URL extracted from body/query is on a
  trusted origin. Errors: `400 INVALID_CALLBACK_URL`, `INVALID_REDIRECT_URL`,
  `INVALID_ERROR_CALLBACK_URL`, `INVALID_NEW_USER_CALLBACK_URL`,
  `403 INVALID_ORIGIN`.

---

## Canonical error codes

All codes in `reference/packages/core/src/error/codes.ts::BASE_ERROR_CODES`
are valid `code` values for `APIError`. The mapping is:

```
USER_NOT_FOUND, FAILED_TO_CREATE_USER, FAILED_TO_CREATE_SESSION,
FAILED_TO_UPDATE_USER, FAILED_TO_GET_SESSION,
INVALID_PASSWORD, INVALID_EMAIL, INVALID_EMAIL_OR_PASSWORD, INVALID_USER,
SOCIAL_ACCOUNT_ALREADY_LINKED, PROVIDER_NOT_FOUND,
INVALID_TOKEN, TOKEN_EXPIRED, ID_TOKEN_NOT_SUPPORTED,
FAILED_TO_GET_USER_INFO, USER_EMAIL_NOT_FOUND, EMAIL_NOT_VERIFIED,
PASSWORD_TOO_SHORT, PASSWORD_TOO_LONG,
USER_ALREADY_EXISTS, USER_ALREADY_EXISTS_USE_ANOTHER_EMAIL,
EMAIL_CAN_NOT_BE_UPDATED, CHANGE_EMAIL_DISABLED,
CREDENTIAL_ACCOUNT_NOT_FOUND, SESSION_EXPIRED,
FAILED_TO_UNLINK_LAST_ACCOUNT, ACCOUNT_NOT_FOUND,
USER_ALREADY_HAS_PASSWORD, CROSS_SITE_NAVIGATION_LOGIN_BLOCKED,
VERIFICATION_EMAIL_NOT_ENABLED, EMAIL_ALREADY_VERIFIED, EMAIL_MISMATCH,
SESSION_NOT_FRESH, LINKED_ACCOUNT_ALREADY_EXISTS,
INVALID_ORIGIN, INVALID_CALLBACK_URL, INVALID_REDIRECT_URL,
INVALID_ERROR_CALLBACK_URL, INVALID_NEW_USER_CALLBACK_URL,
MISSING_OR_NULL_ORIGIN, CALLBACK_URL_REQUIRED,
FAILED_TO_CREATE_VERIFICATION, FIELD_NOT_ALLOWED,
ASYNC_VALIDATION_NOT_SUPPORTED, VALIDATION_ERROR, MISSING_FIELD,
METHOD_NOT_ALLOWED_DEFER_SESSION_REQUIRED, BODY_MUST_BE_AN_OBJECT,
PASSWORD_ALREADY_SET
```

HTTP status comes from the first argument to `APIError.from(...)`:
`BAD_REQUEST` (400), `UNAUTHORIZED` (401), `FORBIDDEN` (403), `NOT_FOUND`
(404), `METHOD_NOT_ALLOWED` (405), `UNPROCESSABLE_ENTITY` (422),
`EXPECTATION_FAILED` (417), `INTERNAL_SERVER_ERROR` (500).

Error response body shape (better-call default):
```json
{
  "message": "...",
  "code": "INVALID_TOKEN",
  "status": 400,
  "statusText": "..."
}
```

---

## Wire-protocol invariants for the Python port

1. Email is always lowercased before adapter queries.
2. Password is hashed even on lookup-failure code paths.
3. `setSessionCookie` writes both `session_token` (signed cookie) and
   `session_data` (cookie cache when enabled). `dontRememberMe` skips
   `maxAge` and writes `dont_remember`.
4. OAuth `redirectURI` is fixed at `${baseURL}/callback/${provider.id}`.
5. JWT-based tokens (verify-email, change-email) are HS256 over
   `ctx.context.secret`; verification-table tokens use `generateId(24)`
   prefixed by purpose (`reset-password:<id>`).
6. All endpoints return JSON unless they explicitly call `ctx.redirect`.
