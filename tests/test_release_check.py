from pathlib import Path
from runpy import run_path


def test_release_version_accepts_zero_major_semver():
    script = Path(__file__).resolve().parents[1] / "scripts" / "release_check.py"
    namespace = run_path(str(script))
    is_release_version = namespace["_is_release_version"]

    assert is_release_version("0.11.0")
    assert is_release_version("1.2.3")
    assert not is_release_version("0.11")
    assert not is_release_version("01.2.3")


def test_tagged_release_rejects_unreleased_changelog():
    script = Path(__file__).resolve().parents[1] / "scripts" / "release_check.py"
    namespace = run_path(str(script))
    check_changelog = namespace["_check_changelog"]
    errors = []

    check_changelog("0.11.0", "v0.11.0", errors)

    assert errors == ["CHANGELOG.md must date 0.11.0 before creating v0.11.0"]


def test_pull_request_ref_is_not_treated_as_release_tag(monkeypatch):
    script = Path(__file__).resolve().parents[1] / "scripts" / "release_check.py"
    namespace = run_path(str(script))
    tag_from_environment = namespace["_tag_from_environment"]
    monkeypatch.setenv("GITHUB_REF", "refs/pull/1/merge")
    monkeypatch.setenv("GITHUB_REF_NAME", "1/merge")
    monkeypatch.setenv("GITHUB_REF_TYPE", "branch")

    assert tag_from_environment() is None


def test_tag_ref_is_used_for_release_validation(monkeypatch):
    script = Path(__file__).resolve().parents[1] / "scripts" / "release_check.py"
    namespace = run_path(str(script))
    tag_from_environment = namespace["_tag_from_environment"]
    monkeypatch.setenv("GITHUB_REF", "refs/tags/v0.11.0")
    monkeypatch.setenv("GITHUB_REF_NAME", "v0.11.0")
    monkeypatch.setenv("GITHUB_REF_TYPE", "tag")

    assert tag_from_environment() == "v0.11.0"
