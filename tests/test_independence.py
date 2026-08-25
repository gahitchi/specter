"""Phase-5a source-independence tracking: correlated sources collapse to one
independence class, the breadth shadow reflects it, and the official score is
unchanged until the config flag flips (shadow-first)."""

import dataclasses
from types import SimpleNamespace

from recon.config import SETTINGS
from recon.correlate.confidence import entity_confidence
from recon.trust import independence
from recon.trust.independence import class_of, independence_breadth, independent_classes


def _obs(source, verdict="FOUND", confidence=0.8, reliability=0.9):
    return SimpleNamespace(source=source, verdict=verdict,
                           confidence=confidence, reliability=reliability)


def test_class_of_groups_rir_and_github():
    assert class_of("asn") == class_of("ripestat") == class_of("ip_geo") == "rir"
    assert class_of("github:user") == class_of("github") == "github"
    # Each username platform is independent.
    assert class_of("username:GitHub") == "site:github"
    assert class_of("username:Keybase") != class_of("username:GitHub")


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


def test_entity_confidence_shadow_is_lower_official_unchanged():
    obs = [_obs("asn"), _obs("ripestat"), _obs("ip_geo")]
    bd = entity_confidence(obs, flags=[])             # flag off by default
    # Official keeps name-based breadth; shadow uses the (smaller) class breadth.
    assert bd.shadow_total is not None
    assert bd.shadow_total < bd.total
    assert any(c.term == "breadth" for c in bd.contributions)


def test_flip_applies_class_breadth_to_official():
    obs = [_obs("asn"), _obs("ripestat"), _obs("ip_geo")]
    flipped = dataclasses.replace(SETTINGS, confidence_independence=True)
    bd = entity_confidence(obs, flags=[], settings=flipped)
    # Now the official score collapses the correlated sources (no breadth bonus).
    breadth = next(c.delta for c in bd.contributions if c.term == "breadth")
    assert breadth == 0.0


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
