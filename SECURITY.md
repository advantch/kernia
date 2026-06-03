# Security Policy

Kernia is authentication infrastructure. We take security reports seriously and
appreciate responsible disclosure.

## Supported versions

Kernia is pre-1.0. Security fixes land on `main` and ship in the next release.
Until 1.0, only the latest released minor receives fixes.

| Version | Supported          |
| ------- | ------------------ |
| latest  | :white_check_mark: |
| < latest| :x:                |

## Reporting a vulnerability

**Do not open a public issue for security vulnerabilities.**

Report privately via GitHub's [private vulnerability reporting](https://github.com/advantch/kernia/security/advisories/new)
(Security → Advisories → Report a vulnerability), or email **security@advantch.com**.

Please include:

- A description of the vulnerability and its impact.
- Steps to reproduce (a minimal `KerniaOptions` config + request sequence is ideal).
- The affected package(s) and version(s).
- Any suggested remediation.

We aim to acknowledge reports within **3 business days** and to ship a fix or a
mitigation plan within **30 days** for confirmed high-severity issues.

## Scope

In scope:

- The `kernia` core and all first-party `kernia-*` packages in this repository.
- Cryptographic handling: cookie signing, password hashing (argon2id/scrypt),
  OAuth state/PKCE, JWT/JWKS issuance and verification, OAuth-token-at-rest
  encryption, WebAuthn attestation/assertion verification, SAML signature
  validation.
- Session lifecycle, CSRF / trusted-origins enforcement, rate limiting.

Out of scope:

- The `examples/` reference app (demonstration only; uses an in-memory adapter
  and a hardcoded dev secret — never deploy it as-is).
- Vulnerabilities that require a misconfiguration explicitly warned against in
  the docs (e.g. disabling CSRF, shipping the dev secret).

## Hardening guidance

Operators should:

- Set a strong, rotated `secret` (use `kernia secret`); see
  [secret rotation](https://docs-advantch.vercel.app/docs/concepts/security).
- Keep `trusted_origins` tight and leave the default CSRF check on.
- Enable `account.encrypt_oauth_tokens` when storing third-party tokens.
- Run behind HTTPS so `Secure` cookies are honoured.
- Pin Kernia and its adapters to known-good versions and watch releases.
