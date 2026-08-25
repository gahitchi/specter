"""Shared, bounded extraction for directly retrieved public web documents.

The parser separates visible content from scripts and styles, resolves only
public HTTP(S) links, and exposes structured data without deciding identity.
Modules remain responsible for deciding which extracted values are evidence.
"""

from __future__ import annotations

import ipaddress
import json
import re
from dataclasses import asdict, dataclass
from html.parser import HTMLParser
from typing import Any, Iterator
from urllib.parse import unquote, urljoin, urlsplit, urlunsplit

import phonenumbers

from . import normalize

_EMAIL_RE = re.compile(r"[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
_IDENTITY_TYPES = {"person", "profilepage"}
_HIDDEN_TAGS = {"script", "style", "noscript", "template"}
_MAX_JSON_RECORDS = 200
_MAX_PHONE_MATCH_TRIES = 120
_MAX_CONTEXT = 260
_MAX_LINKS = 500
_MAX_VISIBLE_CHARS = 512_000
_MAX_JSON_BLOBS = 50
_MAX_JSON_BLOB_CHARS = 100_000
_MAX_TITLE_CHARS = 2_000


@dataclass(frozen=True)
class WebLink:
    url: str
    text: str = ""
    location: str = "anchor[href]"


@dataclass(frozen=True)
class SocialProfile:
    host: str
    username: str
    url: str


@dataclass(frozen=True)
class ExtractedValue:
    value: str
    location: str
    context: str = ""


@dataclass(frozen=True)
class WebDocument:
    base_url: str
    title: str
    visible_text: str
    links: tuple[WebLink, ...]
    email_links: tuple[str, ...]
    telephone_links: tuple[str, ...]
    metadata: dict[str, str]
    json_ld: tuple[Any, ...]
    parser_limited: bool = False


@dataclass(frozen=True)
class StructuredPhoneMatch:
    types: list[str]
    name: str | None
    email: str | None
    urls: list[str]
    address: Any
    identity_record: bool

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


class _DocumentParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.visible: list[str] = []
        self.title_parts: list[str] = []
        self.title_depth = 0
        self.hidden: list[str] = []
        self.json_buffer: list[str] | None = None
        self.json_blobs: list[str] = []
        self.raw_links: list[tuple[str, str]] = []
        self.current_href: str | None = None
        self.current_link_text: list[str] = []
        self.metadata: dict[str, str] = {}
        self.visible_chars = 0
        self.json_chars = 0
        self.limited = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        tag = tag.casefold()
        values = {key.casefold(): value or "" for key, value in attrs}
        if tag == "a":
            if len(self.raw_links) >= _MAX_LINKS:
                self.limited = True
            self.current_href = (
                values.get("href") or None
                if len(self.raw_links) < _MAX_LINKS else None
            )
            self.current_link_text = []
        if tag == "title":
            self.title_depth += 1
        if tag == "meta" and len(self.metadata) < 40:
            key = (values.get("property") or values.get("name") or "").strip().casefold()
            content = collapse_text(values.get("content", ""))[:500]
            if key and content:
                self.metadata.setdefault(key, content)
        if tag == "script":
            content_type = values.get("type", "").split(";", 1)[0].strip().casefold()
            if content_type == "application/ld+json":
                self.json_buffer = []
        if tag in _HIDDEN_TAGS:
            self.hidden.append(tag)

    def handle_data(self, data: str) -> None:
        if self.json_buffer is not None:
            remaining = _MAX_JSON_BLOB_CHARS - self.json_chars
            if remaining > 0:
                self.json_buffer.append(data[:remaining])
                self.json_chars += min(len(data), remaining)
            if len(data) > remaining:
                self.limited = True
        if self.title_depth and sum(map(len, self.title_parts)) < _MAX_TITLE_CHARS:
            self.title_parts.append(data[:_MAX_TITLE_CHARS])
        if self.current_href is not None and not self.hidden:
            if sum(map(len, self.current_link_text)) < 300:
                self.current_link_text.append(data[:300])
        if not self.hidden:
            remaining = _MAX_VISIBLE_CHARS - self.visible_chars
            if remaining > 0:
                self.visible.append(data[:remaining])
                self.visible_chars += min(len(data), remaining)
            if len(data) > remaining:
                self.limited = True

    def handle_endtag(self, tag: str) -> None:
        tag = tag.casefold()
        if tag == "a" and self.current_href is not None:
            if len(self.raw_links) < _MAX_LINKS:
                self.raw_links.append(
                    (self.current_href, collapse_text(" ".join(self.current_link_text))[:300])
                )
            else:
                self.limited = True
            self.current_href = None
            self.current_link_text = []
        if tag == "title" and self.title_depth:
            self.title_depth -= 1
        if tag == "script" and self.json_buffer is not None:
            if len(self.json_blobs) < _MAX_JSON_BLOBS:
                self.json_blobs.append("".join(self.json_buffer))
            else:
                self.limited = True
            self.json_buffer = None
            self.json_chars = 0
        if self.hidden and self.hidden[-1] == tag:
            self.hidden.pop()


def collapse_text(value: str) -> str:
    return re.sub(r"\s+", " ", value or "").strip()


def public_http_url(value: str, base_url: str) -> str | None:
    """Resolve one link and reject local, credential-bearing, or malformed URLs."""
    if not value or len(value) > 2048:
        return None
    resolved = urljoin(base_url, value.strip())
    parts = urlsplit(resolved)
    if parts.scheme.casefold() not in {"http", "https"} or not parts.hostname:
        return None
    if parts.username is not None or parts.password is not None:
        return None
    try:
        parts.port
    except ValueError:
        return None
    host = parts.hostname.rstrip(".").casefold()
    if host == "localhost" or host.endswith((".localhost", ".local")):
        return None
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        address = None
    if address is not None and not address.is_global:
        return None
    return urlunsplit((parts.scheme.casefold(), parts.netloc, parts.path or "/", parts.query, ""))


def response_final_url(response: Any, fallback: str) -> str:
    """Read an HTTP client's final URL while supporting request-less test responses."""
    try:
        candidate = str(response.url)
    except (AttributeError, RuntimeError):
        candidate = fallback
    return public_http_url(candidate, fallback) or fallback


def _normal_email(value: str) -> str | None:
    candidate = unquote(value).strip()
    if candidate.casefold().startswith("mailto:"):
        candidate = candidate[7:]
    candidate = candidate.split("?", 1)[0]
    email = normalize.norm_email(candidate)
    if (
        not email
        or len(email) > 320
        or email.count("@") != 1
        or any(character.isspace() for character in email)
        or not _EMAIL_RE.fullmatch(email)
    ):
        return None
    return email


def parse_web_document(body: str, base_url: str) -> WebDocument:
    parser = _DocumentParser()
    parser.feed(body or "")
    parser.close()

    links: list[WebLink] = []
    emails: list[str] = []
    phones: list[str] = []
    seen_links: set[str] = set()
    for href, text in parser.raw_links:
        folded = href.strip().casefold()
        if folded.startswith("mailto:"):
            email = _normal_email(href)
            if email and email not in emails:
                emails.append(email)
            continue
        if folded.startswith("tel:"):
            value = unquote(href.strip()[4:]).split("?", 1)[0].strip()
            if value and len(value) <= 80 and value not in phones:
                phones.append(value)
            continue
        url = public_http_url(href, base_url)
        if url and url not in seen_links:
            seen_links.add(url)
            links.append(WebLink(url=url, text=text))

    documents: list[Any] = []
    for raw in parser.json_blobs[:_MAX_JSON_BLOBS]:
        if len(raw) > _MAX_JSON_BLOB_CHARS:
            continue
        try:
            documents.append(json.loads(raw))
        except (json.JSONDecodeError, TypeError):
            continue

    title = collapse_text(" ".join(parser.title_parts))[:160]
    if not title:
        title = (
            parser.metadata.get("og:title")
            or parser.metadata.get("twitter:title")
            or ""
        )[:160]
    return WebDocument(
        base_url=base_url,
        title=title,
        visible_text=collapse_text(" ".join(parser.visible)),
        links=tuple(links),
        email_links=tuple(emails),
        telephone_links=tuple(phones),
        metadata=dict(parser.metadata),
        json_ld=tuple(documents),
        parser_limited=parser.limited,
    )


def iter_json_records(documents: tuple[Any, ...] | list[Any]) -> Iterator[dict[str, Any]]:
    stack: list[Any] = list(reversed(documents))
    visited = 0
    while stack and visited < _MAX_JSON_RECORDS:
        item = stack.pop()
        if isinstance(item, dict):
            visited += 1
            yield item
            stack.extend(reversed(list(item.values())[:400]))
        elif isinstance(item, list):
            stack.extend(reversed(item[:400]))


def extract_emails(document: WebDocument, *, limit: int = 10) -> list[str]:
    return [item.value for item in extract_email_values(document, limit=limit)]


def extract_email_values(
    document: WebDocument, *, limit: int = 10
) -> list[ExtractedValue]:
    extracted: list[ExtractedValue] = [
        ExtractedValue(value=email, location="anchor[href^=mailto]")
        for email in document.email_links[:limit]
    ]
    emails = [item.value for item in extracted]
    for candidate in _EMAIL_RE.findall(document.visible_text):
        email = _normal_email(candidate)
        if email and email not in emails:
            emails.append(email)
            extracted.append(ExtractedValue(
                value=email,
                location="visible-text",
                context=email,
            ))
        if len(emails) >= limit:
            return extracted[:limit]
    for record in iter_json_records(document.json_ld):
        value = record.get("email")
        values = value if isinstance(value, list) else [value]
        for candidate in values:
            if not isinstance(candidate, str):
                continue
            email = _normal_email(candidate)
            if email and email not in emails:
                emails.append(email)
                extracted.append(ExtractedValue(
                    value=email,
                    location="json-ld.email",
                    context="structured data",
                ))
            if len(emails) >= limit:
                return extracted[:limit]
    return extracted[:limit]


def _profile_from_url(url: str) -> SocialProfile | None:
    parts = urlsplit(url)
    host = (parts.hostname or "").casefold().removeprefix("www.")
    segments = [segment for segment in parts.path.split("/") if segment]
    username: str | None = None
    if host in {"github.com", "gitlab.com", "x.com", "twitter.com", "instagram.com", "keybase.io"}:
        username = segments[0] if segments else None
    elif host == "mastodon.social" and segments:
        username = segments[0].lstrip("@")
    if not username or not re.fullmatch(r"[A-Za-z0-9_.-]{1,80}", username):
        return None
    return SocialProfile(host=host, username=username.casefold(), url=url)


def extract_social_profiles(document: WebDocument, *, limit: int = 25) -> list[SocialProfile]:
    return [item[0] for item in extract_social_profile_values(document, limit=limit)]


def extract_social_profile_values(
    document: WebDocument, *, limit: int = 25
) -> list[tuple[SocialProfile, ExtractedValue]]:
    urls = [(link.url, link.location, link.text) for link in document.links]
    for record in iter_json_records(document.json_ld):
        value = record.get("sameAs")
        values = value if isinstance(value, list) else [value]
        for candidate in values:
            if isinstance(candidate, str):
                url = public_http_url(candidate, document.base_url)
                if url:
                    urls.append((url, "json-ld.sameAs", "structured data"))

    profiles: list[tuple[SocialProfile, ExtractedValue]] = []
    seen: set[tuple[str, str]] = set()
    for url, location, context in urls:
        profile = _profile_from_url(url)
        if not profile or (profile.host, profile.username) in seen:
            continue
        seen.add((profile.host, profile.username))
        profiles.append((
            profile,
            ExtractedValue(value=url, location=location, context=context[:300]),
        ))
        if len(profiles) >= limit:
            break
    return profiles


def matching_phone_span(
    text: str,
    target_e164: str,
    region: str | None,
) -> tuple[int, int] | None:
    if not text:
        return None
    for match in phonenumbers.PhoneNumberMatcher(
        text,
        region,
        max_tries=_MAX_PHONE_MATCH_TRIES,
    ):
        if (
            phonenumbers.is_valid_number(match.number)
            and phonenumbers.format_number(
                match.number, phonenumbers.PhoneNumberFormat.E164
            ) == target_e164
        ):
            return match.start, match.end

    candidate = text.strip()
    if len(candidate) <= 80:
        try:
            number = phonenumbers.parse(candidate, region)
        except phonenumbers.NumberParseException:
            return None
        if (
            phonenumbers.is_valid_number(number)
            and phonenumbers.format_number(
                number, phonenumbers.PhoneNumberFormat.E164
            ) == target_e164
        ):
            return 0, len(candidate)
    return None


def phone_context(text: str, span: tuple[int, int] | None) -> str | None:
    if not span:
        return None
    start, end = span
    margin = max(20, (_MAX_CONTEXT - (end - start)) // 2)
    snippet = text[max(0, start - margin):min(len(text), end + margin)]
    if start - margin > 0:
        snippet = f"...{snippet}"
    if end + margin < len(text):
        snippet = f"{snippet}..."
    return collapse_text(snippet)[:_MAX_CONTEXT]


def _phone_values(record: dict[str, Any]) -> list[str]:
    values: list[str] = []

    def add(value: Any) -> None:
        if isinstance(value, (str, int)) and not isinstance(value, bool):
            values.append(str(value))
        elif isinstance(value, list):
            for item in value[:20]:
                add(item)

    add(record.get("telephone"))
    add(record.get("phone"))
    contacts = record.get("contactPoint")
    if isinstance(contacts, dict):
        contacts = [contacts]
    if isinstance(contacts, list):
        for contact in contacts[:20]:
            if isinstance(contact, dict):
                add(contact.get("telephone"))
                add(contact.get("phone"))
    return values


def _record_types(record: dict[str, Any]) -> list[str]:
    value = record.get("@type")
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [item for item in value if isinstance(item, str)][:10]
    return []


def find_structured_phone_match(
    document: WebDocument,
    target_e164: str,
    region: str | None,
) -> StructuredPhoneMatch | None:
    for record in iter_json_records(document.json_ld):
        if not any(
            matching_phone_span(value, target_e164, region)
            for value in _phone_values(record)
        ):
            continue

        types = _record_types(record)
        name = record.get("name") if isinstance(record.get("name"), str) else None
        if name:
            name = collapse_text(name)[:160]

        email_value = record.get("email")
        if isinstance(email_value, list):
            email_value = next(
                (item for item in email_value if isinstance(item, str)),
                None,
            )
        email = _normal_email(email_value) if isinstance(email_value, str) else None

        urls: list[str] = []
        for value in (record.get("url"), record.get("sameAs")):
            values = value if isinstance(value, list) else [value]
            for candidate in values[:20]:
                if not isinstance(candidate, str):
                    continue
                url = public_http_url(candidate, document.base_url)
                if url and url not in urls:
                    urls.append(url)

        address = record.get("address")
        if address is not None:
            try:
                if len(json.dumps(address, ensure_ascii=True)) > 2000:
                    address = None
            except (TypeError, ValueError):
                address = None
        return StructuredPhoneMatch(
            types=types,
            name=name,
            email=email,
            urls=urls[:10],
            address=address,
            identity_record=bool(
                {item.casefold() for item in types} & _IDENTITY_TYPES
            ),
        )
    return None
