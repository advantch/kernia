"""Social (OAuth2) providers.

Mirrors `reference/packages/core/src/social-providers/`. Each provider is a
function that returns an `OAuthProvider` value. The full upstream provider list
is exposed here; per-provider tests in `packages/core/tests/social_providers/`
verify each constructor builds a valid authorize URL.
"""

from kernia.social_providers._base import OAuthProvider, OAuthUserProfile
from kernia.social_providers.apple import apple
from kernia.social_providers.atlassian import atlassian
from kernia.social_providers.cognito import cognito
from kernia.social_providers.discord import discord
from kernia.social_providers.dropbox import dropbox
from kernia.social_providers.facebook import facebook
from kernia.social_providers.figma import figma
from kernia.social_providers.github import github
from kernia.social_providers.gitlab import gitlab
from kernia.social_providers.google import google
from kernia.social_providers.huggingface import huggingface
from kernia.social_providers.kakao import kakao
from kernia.social_providers.kick import kick
from kernia.social_providers.line import line
from kernia.social_providers.linear import linear
from kernia.social_providers.linkedin import linkedin
from kernia.social_providers.microsoft import microsoft
from kernia.social_providers.naver import naver
from kernia.social_providers.notion import notion
from kernia.social_providers.paybin import paybin
from kernia.social_providers.paypal import paypal
from kernia.social_providers.polar import polar
from kernia.social_providers.railway import railway
from kernia.social_providers.reddit import reddit
from kernia.social_providers.roblox import roblox
from kernia.social_providers.salesforce import salesforce
from kernia.social_providers.slack import slack
from kernia.social_providers.spotify import spotify
from kernia.social_providers.tiktok import tiktok
from kernia.social_providers.twitch import twitch
from kernia.social_providers.twitter import twitter
from kernia.social_providers.vercel import vercel
from kernia.social_providers.vk import vk
from kernia.social_providers.wechat import wechat
from kernia.social_providers.zoom import zoom

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
