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
