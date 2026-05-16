"""Social (OAuth2) providers.

Mirrors `reference/packages/better-auth/src/social-providers/`. Each provider is a
function that returns an `OAuthProvider` value. The MVP ships Google; the directory
locks the layout for the other 40+ providers in the reference.
"""

from better_auth.social_providers._base import OAuthProvider, OAuthUserProfile
from better_auth.social_providers.google import google

__all__ = ["OAuthProvider", "OAuthUserProfile", "google"]
