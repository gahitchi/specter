"""Centralized identity-field normalization (#2).

A single source of truth for canonicalizing identifiers so that data merged from
different collectors/tools doesn't produce duplicates or mismatched formats.
Used by Query.normalized() and the correlation resolver, so discovery and
correlation agree on what "the same value" means.
"""

from __future__ import annotations

import re
import ipaddress
from urllib.parse import urlsplit, urlunsplit

import phonenumbers

_WS = re.compile(r"\s+")

# Platform aliases -> canonical name (extend as the site dataset grows).
_PLATFORM_ALIASES = {
    "x": "twitter", "x.com": "twitter", "twitter.com": "twitter",
    "github.com": "github", "gitlab.com": "gitlab",
    "mastodon.social": "mastodon", "news.ycombinator.com": "hackernews",
    "hub.docker.com": "dockerhub", "docker hub": "dockerhub",
}


def norm_text(s: str | None) -> str | None:
    if not s:
        return None
    s = _WS.sub(" ", s).strip()
    return s or None


def norm_username(s: str | None) -> str | None:
    """Lowercase, strip a leading @ and surrounding URL/space noise.

    Keeps the raw handle characters (dots/dashes/underscores are significant on
    some platforms) — we only fold case and strip obvious decoration.
    """
    s = norm_text(s)
    if not s:
        return None
    s = s.lstrip("@").strip("/")
    if "/" in s:  # pasted a profile URL
        s = s.rstrip("/").rsplit("/", 1)[-1].lstrip("@")
    return s.lower() or None


def fold_handle(s: str | None) -> str | None:
    """Aggressive fold for cross-platform comparison: alphanumerics only.

    Use for matching the *same person's* handle across sites (where '.'/'_' vary),
    NOT for building URLs."""
    s = norm_username(s)
    if not s:
        return None
    folded = "".join(ch for ch in s if ch.isalnum())
    return folded or None


def norm_email(s: str | None) -> str | None:
    s = norm_text(s)
    if not s or "@" not in s:
        return None
    local, _, domain = s.rpartition("@")
    return f"{local.lower()}@{norm_domain(domain)}"


def norm_phone(s: str | None) -> str | None:
    """Use E.164 when an international number is valid; preserve invalid input.

    Preserving invalid explicit input lets the phone collector explain the
    validation failure instead of making the identifier disappear silently.
    """
    s = norm_text(s)
    if not s:
        return None
    try:
        number = phonenumbers.parse(s, None)
    except phonenumbers.NumberParseException:
        return s
    if phonenumbers.is_valid_number(number):
        return phonenumbers.format_number(number, phonenumbers.PhoneNumberFormat.E164)
    return s


def norm_domain(s: str | None) -> str | None:
    s = norm_text(s)
    if not s:
        return None
    s = s.lower().strip().rstrip(".")
    if "//" in s:
        s = urlsplit(s).netloc or s
    s = s.split("/")[0]
    if s.startswith("www."):
        s = s[4:]
    return s or None


def norm_ip(s: str | None) -> str | None:
    s = norm_text(s)
    if not s:
        return None
    try:
        return ipaddress.ip_address(s).compressed
    except ValueError:
        return s.casefold()


def norm_url(s: str | None) -> str | None:
    s = norm_text(s)
    if not s:
        return None
    parts = urlsplit(s if "//" in s else f"https://{s}")
    netloc = parts.netloc.lower()
    if netloc.startswith("www."):
        netloc = netloc[4:]
    path = parts.path.rstrip("/")
    # Fragments are client-side state and never identify a different resource.
    # Query strings can be identity-bearing (for example `/user?id=alice`) and
    # must not be discarded during canonicalization.
    return urlunsplit((parts.scheme or "https", netloc, path, parts.query, ""))


def canonical_platform(name: str | None) -> str | None:
    n = norm_text(name)
    if not n:
        return None
    key = n.lower()
    return _PLATFORM_ALIASES.get(key, key)
