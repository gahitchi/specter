"""Conservative single-input classification shared by CLI, API, and UI."""

from __future__ import annotations

import enum
import ipaddress
import re
from typing import Any
from urllib.parse import parse_qs, urlsplit

import phonenumbers
from pydantic import BaseModel, Field

from . import normalize

MAX_INPUT_LENGTH = 320
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f-\x9f]")
_LOCAL_RE = re.compile(r"^[^\s@]{1,64}$")
_HANDLE_RE = re.compile(r"^[\w.-]{1,80}$", re.UNICODE)


class IdentifierKind(str, enum.Enum):
    USERNAME = "username"
    EMAIL = "email"
    PHONE = "phone"
    DOMAIN = "domain"
    NAME = "name"
    URL = "url"
    IP_ADDRESS = "ip_address"


class InputResolution(BaseModel):
    """Auditable interpretation of one user-supplied starting value."""

    mode: str = "automatic"
    kind: IdentifierKind | str
    normalized: str
    confidence: float = Field(ge=0.0, le=1.0)
    reasons: list[str] = Field(default_factory=list)
    alternatives: list[str] = Field(default_factory=list)
    query_fields: dict[str, str] = Field(default_factory=dict)
    derived_fields: list[str] = Field(default_factory=list)


def _clean(value: str) -> str:
    cleaned = str(value).strip()
    if not cleaned:
        raise ValueError("starting value cannot be empty")
    if len(cleaned) > MAX_INPUT_LENGTH:
        raise ValueError(f"starting value exceeds {MAX_INPUT_LENGTH} characters")
    if _CONTROL_RE.search(cleaned):
        raise ValueError("starting value contains control characters")
    return cleaned


def _domain(value: str) -> str | None:
    candidate = normalize.norm_domain(value)
    if not candidate or len(candidate) > 253 or "." not in candidate:
        return None
    try:
        ascii_domain = candidate.encode("idna").decode("ascii")
    except UnicodeError:
        return None
    labels = ascii_domain.split(".")
    if any(
        not label
        or len(label) > 63
        or label.startswith("-")
        or label.endswith("-")
        or not re.fullmatch(r"[a-z0-9-]+", label, re.IGNORECASE)
        for label in labels
    ):
        return None
    if not re.search(r"[a-z]", labels[-1], re.IGNORECASE):
        return None
    return ascii_domain.casefold()


def _email(value: str) -> str | None:
    if value.count("@") != 1:
        return None
    local, domain = value.rsplit("@", 1)
    normalized_domain = _domain(domain)
    if not _LOCAL_RE.fullmatch(local) or not normalized_domain:
        return None
    return f"{local.casefold()}@{normalized_domain}"


def _phone(value: str) -> str | None:
    if not value.startswith("+"):
        return None
    try:
        number = phonenumbers.parse(value, None)
    except phonenumbers.NumberParseException:
        return None
    if not phonenumbers.is_valid_number(number):
        return None
    return phonenumbers.format_number(number, phonenumbers.PhoneNumberFormat.E164)


def _url_fields(value: str) -> tuple[str, dict[str, str], list[str]] | None:
    parts = urlsplit(value)
    if parts.scheme.casefold() not in {"http", "https"} or not parts.hostname:
        return None
    if parts.username is not None or parts.password is not None:
        raise ValueError("credentials embedded in URLs are not allowed")
    normalized = normalize.norm_url(value)
    if not normalized:
        return None
    host = parts.hostname.rstrip(".").casefold()
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        address = None
    if host == "localhost" or host.endswith((".localhost", ".local")):
        raise ValueError("local network URLs are not allowed")
    if address is not None and not address.is_global:
        raise ValueError("non-public IP address URLs are not allowed")

    fields = {"url": normalized}
    derived: list[str] = []
    domain = _domain(host)
    if domain:
        fields["domain"] = domain
        derived.append("domain")

    segments = [segment for segment in parts.path.split("/") if segment]
    handle: str | None = None
    if host in {"github.com", "gitlab.com", "x.com", "twitter.com", "instagram.com", "keybase.io"}:
        handle = segments[0] if segments else None
    elif host == "mastodon.social" and segments:
        handle = segments[0].lstrip("@")
    elif host == "news.ycombinator.com":
        handle = (parse_qs(parts.query).get("id") or [None])[0]
    if handle and _HANDLE_RE.fullmatch(handle):
        fields["username"] = normalize.norm_username(handle) or handle.casefold()
        derived.append("username")
    return normalized, fields, derived


def _hinted(value: str, hint: IdentifierKind) -> InputResolution:
    if hint == IdentifierKind.EMAIL:
        normalized = _email(value)
    elif hint == IdentifierKind.PHONE:
        normalized = _phone(value)
    elif hint == IdentifierKind.DOMAIN:
        normalized = _domain(value)
    elif hint == IdentifierKind.IP_ADDRESS:
        try:
            normalized = ipaddress.ip_address(value).compressed
        except ValueError:
            normalized = None
    elif hint == IdentifierKind.URL:
        url_result = _url_fields(value)
        if url_result:
            normalized, fields, derived = url_result
            return InputResolution(
                kind=hint,
                normalized=normalized,
                confidence=1.0,
                reasons=["type was supplied explicitly and the URL passed safety validation"],
                query_fields=fields,
                derived_fields=derived,
            )
        normalized = None
    elif hint == IdentifierKind.USERNAME:
        normalized = normalize.norm_username(value) if _HANDLE_RE.fullmatch(value.lstrip("@")) else None
    else:
        normalized = normalize.norm_text(value) if any(char.isalpha() for char in value) else None
    if not normalized:
        raise ValueError(f"starting value is not a valid {hint.value}")
    return InputResolution(
        kind=hint,
        normalized=normalized,
        confidence=1.0,
        reasons=["type was supplied explicitly and the value passed validation"],
        query_fields={hint.value: normalized},
    )


def classify_input(value: str, hint: str | IdentifierKind | None = None) -> InputResolution:
    """Classify one value without turning an ambiguous string into several seeds."""
    cleaned = _clean(value)
    if hint is not None:
        try:
            kind = hint if isinstance(hint, IdentifierKind) else IdentifierKind(hint)
        except ValueError as exc:
            choices = ", ".join(kind.value for kind in IdentifierKind)
            raise ValueError(f"unknown input type; choose one of: {choices}") from exc
        return _hinted(cleaned, kind)

    normalized_email = _email(cleaned)
    if normalized_email:
        return InputResolution(
            kind=IdentifierKind.EMAIL,
            normalized=normalized_email,
            confidence=0.99,
            reasons=["contains one valid mailbox and a valid domain"],
            query_fields={"email": normalized_email},
        )

    url_result = _url_fields(cleaned)
    if url_result:
        normalized, fields, derived = url_result
        return InputResolution(
            kind=IdentifierKind.URL,
            normalized=normalized,
            confidence=0.99,
            reasons=["absolute public HTTP(S) URL"],
            query_fields=fields,
            derived_fields=derived,
        )

    try:
        address = ipaddress.ip_address(cleaned)
    except ValueError:
        address = None
    if address is not None:
        return InputResolution(
            kind=IdentifierKind.IP_ADDRESS,
            normalized=address.compressed,
            confidence=1.0,
            reasons=["valid IPv4 or IPv6 address"],
            query_fields={"ip_address": address.compressed},
        )

    normalized_phone = _phone(cleaned)
    if normalized_phone:
        return InputResolution(
            kind=IdentifierKind.PHONE,
            normalized=normalized_phone,
            confidence=0.99,
            reasons=["valid international phone number"],
            query_fields={"phone": normalized_phone},
        )

    normalized_domain = _domain(cleaned)
    if normalized_domain:
        return InputResolution(
            kind=IdentifierKind.DOMAIN,
            normalized=normalized_domain,
            confidence=0.96,
            reasons=["valid domain name"],
            query_fields={"domain": normalized_domain},
        )

    if any(char.isspace() for char in cleaned) and any(char.isalpha() for char in cleaned):
        name = normalize.norm_text(cleaned) or cleaned
        return InputResolution(
            kind=IdentifierKind.NAME,
            normalized=name,
            confidence=0.88,
            reasons=["multiple words are most consistent with a person or organization name"],
            alternatives=[IdentifierKind.USERNAME.value],
            query_fields={"name": name},
        )

    handle = normalize.norm_username(cleaned)
    if handle and _HANDLE_RE.fullmatch(handle):
        return InputResolution(
            kind=IdentifierKind.USERNAME,
            normalized=handle,
            confidence=0.72,
            reasons=["single handle-shaped token; this interpretation remains ambiguous"],
            alternatives=[IdentifierKind.NAME.value],
            query_fields={"username": handle},
        )
    raise ValueError("starting value could not be classified safely")


def describe_query(query: Any) -> dict[str, Any]:
    fields = query.normalized().model_dump(exclude_none=True)
    names = list(fields)
    return InputResolution(
        mode="explicit",
        kind=names[0] if len(names) == 1 else "multiple",
        normalized=str(fields[names[0]]) if len(names) == 1 else f"{len(names)} identifiers",
        confidence=1.0,
        reasons=["identifier type was supplied explicitly"],
        query_fields=fields,
    ).model_dump(mode="json")


def resolve_query(
    subject: str | None = None,
    *,
    hint: str | IdentifierKind | None = None,
    **identifiers: str | None,
) -> tuple[Any, dict[str, Any]]:
    """Merge one auto-classified subject with optional explicitly typed fields."""
    from .models import Query

    explicit = Query(**{key: value for key, value in identifiers.items() if value}).normalized()
    fields = explicit.model_dump(exclude_none=True)
    resolution: InputResolution | None = None
    if subject:
        resolution = classify_input(subject, hint=hint)
        for key, value in resolution.query_fields.items():
            if key in fields and fields[key] != value:
                raise ValueError(f"starting value conflicts with explicit {key}")
            fields.setdefault(key, value)
    query = Query(**fields).normalized()
    if query.is_empty():
        raise ValueError("at least one identifier is required")
    if resolution is None:
        return query, describe_query(query)
    intake = resolution.model_dump(mode="json")
    intake["query_fields"] = query.model_dump(exclude_none=True)
    if set(fields) - set(resolution.query_fields):
        intake["mode"] = "automatic_with_explicit"
    return query, intake
