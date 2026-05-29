"""Social (OAuth2) providers.

Mirrors `reference/packages/core/src/social-providers/`. Each provider is a
function that returns an `OAuthProvider` value. The full upstream provider list
is exposed here; per-provider tests in `packages/core/tests/social_providers/`
verify each constructor builds a valid authorize URL.
"""

from better_auth.social_providers._base import OAuthProvider, OAuthUserProfile
from better_auth.social_providers.apple import apple
from better_auth.social_providers.atlassian import atlassian
from better_auth.social_providers.cognito import cognito
from better_auth.social_providers.discord import discord
from better_auth.social_providers.dropbox import dropbox
from better_auth.social_providers.facebook import facebook
from better_auth.social_providers.figma import figma
from better_auth.social_providers.github import github
from better_auth.social_providers.gitlab import gitlab
from better_auth.social_providers.google import google
from better_auth.social_providers.huggingface import huggingface
from better_auth.social_providers.kakao import kakao
from better_auth.social_providers.kick import kick
from better_auth.social_providers.line import line
from better_auth.social_providers.linear import linear
from better_auth.social_providers.linkedin import linkedin
from better_auth.social_providers.microsoft import microsoft
from better_auth.social_providers.naver import naver
from better_auth.social_providers.notion import notion
from better_auth.social_providers.paybin import paybin
from better_auth.social_providers.paypal import paypal
from better_auth.social_providers.polar import polar
from better_auth.social_providers.railway import railway
from better_auth.social_providers.reddit import reddit
from better_auth.social_providers.roblox import roblox
from better_auth.social_providers.salesforce import salesforce
from better_auth.social_providers.slack import slack
from better_auth.social_providers.spotify import spotify
from better_auth.social_providers.tiktok import tiktok
from better_auth.social_providers.twitch import twitch
from better_auth.social_providers.twitter import twitter
from better_auth.social_providers.vercel import vercel
from better_auth.social_providers.vk import vk
from better_auth.social_providers.wechat import wechat
from better_auth.social_providers.zoom import zoom

__all__ = [
    "OAuthProvider",
    "OAuthUserProfile",
    "apple",
    "atlassian",
    "cognito",
    "discord",
    "dropbox",
    "facebook",
    "figma",
    "github",
    "gitlab",
    "google",
    "huggingface",
    "kakao",
    "kick",
    "line",
    "linear",
    "linkedin",
    "microsoft",
    "naver",
    "notion",
    "paybin",
    "paypal",
    "polar",
    "railway",
    "reddit",
    "roblox",
    "salesforce",
    "slack",
    "spotify",
    "tiktok",
    "twitch",
    "twitter",
    "vercel",
    "vk",
    "wechat",
    "zoom",
]
