"""Correlated source views collapse to one official independence class."""

import dataclasses
from types import SimpleNamespace

from recon.config import SETTINGS
from recon.correlate.confidence import entity_confidence
from recon.trust import independence
from recon.trust.independence import (
    class_of,
    class_of_observation,
    independence_breadth,
    independent_classes,
)


def _obs(source, verdict="FOUND", confidence=0.8, reliability=0.9):
    return SimpleNamespace(source=source, verdict=verdict,
                           confidence=confidence, reliability=reliability,
                           signals={"email": "shared@example.com"})


def test_class_of_groups_rir_and_github():
    assert class_of("asn") == class_of("ripestat") == class_of("ip_geo") == "rir"
    assert class_of("github:user") == class_of("github") == "github"
    # Each username platform is independent.
    assert class_of("username:GitHub") == "github"
    assert class_of("profile:enrich github.com") == "github"
    assert class_of("external:maigret:GitHub") == "github"
    assert class_of("username:Keybase") != class_of("username:GitHub")
    old = SimpleNamespace(
        source="profile:enrich", independence_key="site:github.com", origin=None
    )
    assert class_of_observation(old) == "github"


def test_phone_web_is_independent_from_offline_numbering_metadata():
    assert class_of("phone:validate") == "phone_offline"
    assert class_of("phone:web") == "public_web"


def test_independent_classes_collapses_redundant():
    classes, redundant = independent_classes(["asn", "ripestat", "ip_geo"])
    assert classes == {"rir"}
    assert len(redundant) == 2                       # two of the three are redundant


def test_independence_breadth_below_name_breadth_for_correlated():
    sources = ["asn", "ripestat", "ip_geo"]
    name_breadth = min(0.25, 0.08 * (len(set(sources)) - 1))   # 0.16
    assert independence_breadth(sources) < name_breadth        # 0.0 < 0.16


def test_entity_confidence_uses_independence_and_caps_one_upstream():
    obs = [_obs("asn"), _obs("ripestat"), _obs("ip_geo")]
    bd = entity_confidence(obs, flags=[])
    assert bd.shadow_total is not None
    assert bd.total == SETTINGS.identity_single_origin_cap
    assert bd.shadow_total == SETTINGS.identity_single_origin_cap
    assert next(c.delta for c in bd.contributions if c.term == "breadth") == 0.0
    assert any(c.term == "single_origin_cap" for c in bd.contributions)


def test_legacy_connector_count_can_only_change_the_audit_breakdown():
    obs = [_obs("asn"), _obs("ripestat"), _obs("ip_geo")]
    legacy = dataclasses.replace(SETTINGS, confidence_independence=False)
    bd = entity_confidence(obs, flags=[], settings=legacy)
    breadth = next(c.delta for c in bd.contributions if c.term == "breadth")
    assert breadth == 0.16
    assert bd.total == SETTINGS.identity_single_origin_cap


def test_truly_independent_sources_keep_breadth():
    obs = [_obs("username:GitHub"), _obs("gravatar"), _obs("breach")]
    bd = entity_confidence(obs, flags=[])
    breadth = next(c.delta for c in bd.contributions if c.term == "breadth")
    assert breadth > 0.0                              # 3 distinct classes


def test_override_file_changes_class(tmp_path, monkeypatch):
    f = tmp_path / "indep.json"
    f.write_text('{"gravatar": "avatars"}')
    monkeypatch.setenv("RECON_INDEPENDENCE_FILE", str(f))
    independence.reload()
    try:
        assert class_of("gravatar") == "avatars"
    finally:
        monkeypatch.delenv("RECON_INDEPENDENCE_FILE", raising=False)
        independence.reload()
