import pytest
from pathlib import Path

from recon.web_document import (
    extract_emails,
    extract_social_profiles,
    find_structured_phone_match,
    parse_web_document,
    public_http_url,
)


def test_document_extracts_visible_and_structured_values_without_script_decoys():
    document = parse_web_document(
        """
        <html><head><meta property="og:title" content="Alice profile"></head><body>
          <p>Email <a href="MAILTO:Alice%40Example.com?subject=Hello">Alice</a></p>
          <a href="/contact#team">Contact</a>
          <a href="https://github.com/Alice.Example">GitHub</a>
          <a href="http://127.0.0.1/private">private</a>
          <script>const decoy = "hidden@example.net";</script>
          <script type="application/ld+json">
            {"@type":"Person","sameAs":"https://x.com/alice_example"}
          </script>
        </body></html>
        """,
        "https://alice.example/about",
    )

    assert document.title == "Alice profile"
    assert "hidden@example.net" not in document.visible_text
    assert extract_emails(document) == ["alice@example.com"]
    assert [link.url for link in document.links] == [
        "https://alice.example/contact",
        "https://github.com/Alice.Example",
    ]
    assert {(profile.host, profile.username) for profile in extract_social_profiles(document)} == {
        ("github.com", "alice.example"),
        ("x.com", "alice_example"),
    }


def test_structured_phone_match_requires_same_json_record():
    document = parse_web_document(
        """
        <script type="application/ld+json">
        [
          {"@type":"Person","name":"Wrong person","email":"wrong@example.com"},
          {
            "@type":"Person",
            "name":"Alice Example",
            "telephone":"+1 415 555 2671",
            "email":"alice@example.com",
            "sameAs":["https://github.com/alice"]
          }
        ]
        </script>
        """,
        "https://directory.example/alice",
    )

    match = find_structured_phone_match(document, "+14155552671", "US")

    assert match is not None
    assert match.identity_record is True
    assert match.name == "Alice Example"
    assert match.email == "alice@example.com"
    assert match.urls == ["https://github.com/alice"]


@pytest.mark.parametrize(
    "value",
    [
        "http://127.0.0.1/private",
        "http://[::1]/private",
        "https://user:pass@example.com/",
        "file:///tmp/report",
        "https://localhost/profile",
    ],
)
def test_public_url_rejects_local_or_credential_bearing_targets(value):
    assert public_http_url(value, "https://example.com/") is None


def test_malformed_json_ld_is_ignored():
    document = parse_web_document(
        '<script type="application/ld+json">{not json}</script><p>Public text</p>',
        "https://example.com/",
    )

    assert document.json_ld == ()
    assert document.visible_text == "Public text"


def test_parser_applies_hard_bounds_to_adversarial_documents():
    body = "<p>" + ("x" * 600_000) + "</p>" + "".join(
        f'<a href="https://example.com/{index}">link</a>' for index in range(800)
    )
    document = parse_web_document(body, "https://example.com/")

    assert len(document.visible_text) <= 512_000
    assert len(document.links) <= 500
    assert document.parser_limited is True


def test_sanitized_profile_replay_is_deterministic():
    fixture = Path(__file__).parent / "fixtures" / "web" / "profile_replay.html"
    first = parse_web_document(fixture.read_text(encoding="utf-8"), "https://example.com/alice")
    second = parse_web_document(fixture.read_text(encoding="utf-8"), "https://example.com/alice")

    assert first == second
    assert extract_emails(first) == ["alice@example.com"]
