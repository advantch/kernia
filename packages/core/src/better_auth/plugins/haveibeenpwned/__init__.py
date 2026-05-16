"""Have-I-Been-Pwned password compromise plugin.

Mirrors `reference/packages/better-auth/src/plugins/haveibeenpwned/index.ts`.
Hashes the candidate password (SHA-1), sends the first 5 hex chars to the
pwnedpasswords range API, and rejects the request if the remainder appears in
the response.
"""

from better_auth.plugins.haveibeenpwned.plugin import have_i_been_pwned

__all__ = ["have_i_been_pwned"]
