"""one_time_token — see reference/packages/better-auth/src/plugins/one-time-token/.

Generates a single-use disposable token bound to a session's user id + a caller
provided purpose string. Backed by the `verification` core table.
"""

from better_auth.plugins.one_time_token.plugin import (
    ONE_TIME_TOKEN_ERROR_CODES,
    one_time_token,
)

__all__ = ["ONE_TIME_TOKEN_ERROR_CODES", "one_time_token"]
