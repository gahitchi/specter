"""One-value intake classification and typed seed construction."""

import pytest

from recon.graph_models import ArtifactType
from recon.identifiers import classify_input, resolve_query
from recon.models import Query


@pytest.mark.parametrize(
    ("value", "kind", "normalized"),
    [
        ("Alice@Example.COM", "email", "alice@example.com"),
        ("+1 415 555 2671", "phone", "+14155552671"),
        ("WWW.Example.com", "domain", "example.com"),
        ("Ada Lovelace", "name", "Ada Lovelace"),
        ("@Alice", "username", "alice"),
        ("8.8.8.8", "ip_address", "8.8.8.8"),
    ],
)
def test_classifies_common_starting_values(value, kind, normalized) -> None:
    result = classify_input(value)

    assert result.kind == kind
    assert result.normalized == normalized
    assert result.query_fields[kind] == normalized


def test_profile_url_derives_only_a_recognized_handle_and_domain() -> None:
    result = classify_input("https://github.com/Torvalds?tab=repositories#readme")

    assert result.kind == "url"
    assert result.query_fields == {
        "url": "https://github.com/Torvalds?tab=repositories",
        "domain": "github.com",
        "username": "torvalds",
    }
    assert result.derived_fields == ["domain", "username"]


def test_url_intake_rejects_local_network_targets() -> None:
    with pytest.raises(ValueError, match="local network"):
        classify_input("http://localhost/profile")
    with pytest.raises(ValueError, match="non-public"):
        classify_input("https://127.0.0.1/profile")


def test_explicit_hint_validates_instead_of_forcing_a_type() -> None:
    with pytest.raises(ValueError, match="valid email"):
        classify_input("not-an-email", hint="email")
    assert classify_input("single token", hint="name").kind == "name"


def test_configured_region_enables_national_phone_intake() -> None:
    result = classify_input("06 6982", hint="phone", default_phone_region="IT")

    assert result.kind == "phone"
    assert result.normalized == "+39066982"
    assert "configured IT region" in result.reasons[0]


def test_resolution_merges_additional_known_fields_and_rejects_conflicts() -> None:
    query, intake = resolve_query("alice@example.com", name="Alice Example")

    assert query == Query(email="alice@example.com", name="Alice Example")
    assert intake["mode"] == "automatic_with_explicit"
    with pytest.raises(ValueError, match="conflicts with explicit username"):
        resolve_query("https://github.com/alice", username="bob")


def test_query_creates_url_and_ip_seed_artifacts() -> None:
    query = Query(
        url="https://example.com/user?id=alice#details",
        ip_address="2001:4860:4860::8888",
    ).normalized()
    seeds = {seed.type: seed for seed in query.to_seed_artifacts()}

    assert query.url == "https://example.com/user?id=alice"
    assert seeds[ArtifactType.ACCOUNT_PROFILE].value == query.url
    assert seeds[ArtifactType.IP_ADDRESS].normalized == "2001:4860:4860::8888"
