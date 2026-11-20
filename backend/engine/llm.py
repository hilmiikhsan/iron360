"""Anthropic client factory.

Builds the Anthropic SDK client, optionally pointed at an OmniRoute / gateway
endpoint via ANTHROPIC_BASE_URL (must speak the Anthropic Messages API, /v1/messages).
If a gateway needs no key, a placeholder is sent so the SDK constructs cleanly.
"""
from __future__ import annotations

from ..config import get_settings

settings = get_settings()


def make_client():
    import anthropic

    kwargs: dict = {"api_key": settings.anthropic_api_key or "omniroute-gateway"}
    if settings.anthropic_base_url:
        kwargs["base_url"] = settings.anthropic_base_url.rstrip("/")
    return anthropic.Anthropic(**kwargs)
