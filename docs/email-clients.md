# Email clients

Admin config supports SMTP, Resend, and Postmark records behind a common email
client shape. This lets the UI store provider configuration while individual
plugins keep using their normal `send_*` hooks.

## Stored shape

```json
{
  "id": "primary",
  "kind": "postmark",
  "name": "Primary transactional",
  "enabled": true,
  "fromEmail": "auth@example.com",
  "config": {
    "apiKey": "..."
  }
}
```

Supported `kind` values are `smtp`, `resend`, and `postmark`.

## Redaction

Secrets are redacted on read:

```json
{
  "config": {
    "apiKey": "********"
  }
}
```

Write the full value again when rotating a secret. The admin UI should never
attempt to read back or display the original value.
