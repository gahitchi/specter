from __future__ import annotations

import io
import json
import os
from pathlib import Path
import subprocess
import tarfile
import time
import urllib.error

import pytest

from recon import updater

REVISION_A = "a" * 40
REVISION_B = "b" * 40
REVISION_C = "c" * 40


@pytest.fixture
def update_environment(monkeypatch, tmp_path):
    monkeypatch.setenv("SPECTER_UPDATE_DIR", str(tmp_path / "updates"))
    monkeypatch.delenv("RECON_AUTO_UPDATE", raising=False)
    monkeypatch.delenv("RECON_ENV", raising=False)
    monkeypatch.setattr(updater, "_installation_manager", lambda: ("uv", "uv"))
    return tmp_path / "updates"


def _cached_project(root: Path, revision: str) -> Path:
    project = root / revision
    project.mkdir(parents=True)
    (project / "pyproject.toml").write_text("[project]\nname='osint-recon'\n", encoding="utf-8")
    (root / "pending.json").write_text(json.dumps({"revision": revision}), encoding="utf-8")
    return project


def _tar_response(entries: dict[str, bytes], *, size: str | None = None):
    payload = io.BytesIO()
    with tarfile.open(fileobj=payload, mode="w:gz") as archive:
        for name, content in entries.items():
            member = tarfile.TarInfo(name)
            member.size = len(content)
            member.mode = 0o644
            archive.addfile(member, io.BytesIO(content))
    payload.seek(0)

    class Response(io.BytesIO):
        def __init__(self, content):
            super().__init__(content)
            self.headers = {"Content-Length": size or str(len(content))}

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            self.close()

    return Response(payload.read())


def test_update_check_can_be_disabled(monkeypatch):
    monkeypatch.setenv("RECON_AUTO_UPDATE", "0")
    monkeypatch.setattr(
        updater, "_installation_manager", lambda: (_ for _ in ()).throw(AssertionError)
    )

    result = updater.check_for_update()

    assert not result.attempted
    assert result.message == "update checks disabled"


def test_forced_check_overrides_disabled_setting(monkeypatch, update_environment):
    monkeypatch.setenv("RECON_AUTO_UPDATE", "0")
    monkeypatch.setattr(updater, "_installed_revision", lambda: REVISION_A)
    monkeypatch.setattr(updater, "_remote_revision", lambda timeout: REVISION_A)

    result = updater.check_for_update(force=True)

    assert result.attempted
    assert result.message == "Specter is up to date"


def test_update_check_skips_production(monkeypatch):
    monkeypatch.setenv("RECON_ENV", "production")
    monkeypatch.setattr(
        updater, "_installation_manager", lambda: (_ for _ in ()).throw(AssertionError)
    )

    result = updater.check_for_update()

    assert not result.attempted
    assert "production" in result.message


def test_update_check_skips_development_checkout(monkeypatch):
    monkeypatch.setattr(updater, "_installation_manager", lambda: None)

    result = updater.check_for_update()

    assert not result.attempted
    assert not result.message


def test_installation_manager_detects_uv_tool(monkeypatch, tmp_path):
    tool_dir = tmp_path / "tools"
    monkeypatch.setattr(updater.sys, "prefix", str(tool_dir / "osint-recon"))
    monkeypatch.setattr(updater.shutil, "which", lambda name: "uv" if name == "uv" else None)
    monkeypatch.setattr(updater, "_command_output", lambda command: str(tool_dir))

    assert updater._installation_manager() == ("uv", "uv")


def test_installation_manager_detects_pipx(monkeypatch, tmp_path):
    tool_dir = tmp_path / "pipx"
    monkeypatch.setattr(updater.sys, "prefix", str(tool_dir / "osint-recon"))
    monkeypatch.setattr(updater.shutil, "which", lambda name: "pipx" if name == "pipx" else None)
    monkeypatch.setattr(updater, "_command_output", lambda command: str(tool_dir))

    assert updater._installation_manager() == ("pipx", "pipx")


def test_check_downloads_but_does_not_install(monkeypatch, update_environment):
    downloaded: list[tuple[str, float]] = []
    stale = update_environment / REVISION_A
    stale.mkdir(parents=True)
    (stale / "old.txt").write_text("old", encoding="utf-8")
    monkeypatch.setattr(updater, "_installed_revision", lambda: REVISION_A)
    monkeypatch.setattr(updater, "_remote_revision", lambda timeout: REVISION_B)

    def download(revision, timeout):
        downloaded.append((revision, timeout))
        return _cached_project(update_environment, revision)

    monkeypatch.setattr(updater, "_download_revision", download)
    monkeypatch.setattr(
        updater.subprocess,
        "run",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("installed in background")),
    )

    result = updater.check_for_update(timeout=7)

    assert downloaded == [(REVISION_B, 7)]
    assert result.update_available and result.downloaded and not result.applied
    assert json.loads((update_environment / "pending.json").read_text())["revision"] == REVISION_B
    assert not stale.exists()


def test_check_reuses_downloaded_revision(monkeypatch, update_environment):
    _cached_project(update_environment, REVISION_B)
    monkeypatch.setattr(updater, "_installed_revision", lambda: REVISION_A)
    monkeypatch.setattr(updater, "_remote_revision", lambda timeout: REVISION_B)
    monkeypatch.setattr(
        updater, "_download_revision", lambda *_args: (_ for _ in ()).throw(AssertionError)
    )

    result = updater.check_for_update()

    assert result.update_available and not result.downloaded
    assert "is ready" in result.message


def test_manual_build_selection_is_not_replaced_by_automatic_check(
    monkeypatch, update_environment
):
    _cached_project(update_environment, REVISION_B)
    (update_environment / "pending.json").write_text(
        json.dumps({"revision": REVISION_B, "title": "Preferred build", "selected": True}),
        encoding="utf-8",
    )
    monkeypatch.setattr(updater, "_installed_revision", lambda: REVISION_A)
    monkeypatch.setattr(updater, "_remote_revision", lambda timeout: REVISION_C)
    monkeypatch.setattr(
        updater, "_download_revision", lambda *_args: (_ for _ in ()).throw(AssertionError)
    )

    result = updater.check_for_update()

    pending = json.loads((update_environment / "pending.json").read_text())
    assert result.update_available and not result.downloaded
    assert pending["revision"] == REVISION_B
    assert pending["selected"] is True


def test_list_available_builds_returns_readable_github_history(monkeypatch):
    payload = [
        {
            "sha": REVISION_C,
            "commit": {
                "message": "Simplify investigation workspace\n\nDetails",
                "author": {"name": "Specter Team", "date": "2026-08-21T09:30:00Z"},
            },
        },
        {"sha": "invalid", "commit": {"message": "Ignore me"}},
    ]
    response = io.BytesIO(json.dumps(payload).encode())
    monkeypatch.setattr(updater.urllib.request, "urlopen", lambda *_args, **_kwargs: response)

    builds = updater.list_available_builds(limit=500)

    assert builds == [
        updater.AvailableBuild(
            revision=REVISION_C,
            title="Simplify investigation workspace",
            authored_at="2026-08-21T09:30:00Z",
            author="Specter Team",
        )
    ]


def test_download_build_caches_exact_user_selection(monkeypatch, update_environment):
    downloaded: list[tuple[str, float]] = []
    monkeypatch.setattr(updater, "_installed_revision", lambda: REVISION_A)

    def download(revision, timeout):
        downloaded.append((revision, timeout))
        return _cached_project(update_environment, revision)

    monkeypatch.setattr(updater, "_download_revision", download)

    result = updater.download_build(REVISION_B, title="Known stable build", timeout=9)

    pending = json.loads((update_environment / "pending.json").read_text())
    assert downloaded == [(REVISION_B, 9)]
    assert result.downloaded and result.update_available
    assert pending == {
        "revision": REVISION_B,
        "title": "Known stable build",
        "downloaded_at": pending["downloaded_at"],
        "selected": True,
    }


def test_current_revision_clears_stale_pending(monkeypatch, update_environment):
    _cached_project(update_environment, REVISION_B)
    monkeypatch.setattr(updater, "_installed_revision", lambda: REVISION_A)
    monkeypatch.setattr(updater, "_remote_revision", lambda timeout: REVISION_A)

    result = updater.check_for_update()

    assert result.attempted and not result.update_available
    assert not (update_environment / "pending.json").exists()


def test_check_failure_does_not_interrupt_specter(monkeypatch, update_environment):
    monkeypatch.setattr(updater, "_installed_revision", lambda: REVISION_A)
    monkeypatch.setattr(
        updater,
        "_remote_revision",
        lambda timeout: (_ for _ in ()).throw(urllib.error.URLError("offline")),
    )

    result = updater.check_for_update()

    assert result.attempted and not result.update_available
    assert "could not reach GitHub" in result.message
    assert "keep running" in result.message


def test_archive_download_extracts_regular_files(monkeypatch, update_environment):
    response = _tar_response({
        "osint-recon-revision/pyproject.toml": b"[project]\nname='osint-recon'\n",
        "osint-recon-revision/src/recon/__init__.py": b"__version__='1'\n",
    })
    monkeypatch.setattr(updater.urllib.request, "urlopen", lambda *_args, **_kwargs: response)

    project = updater._download_revision(REVISION_A, 5)

    assert (project / "pyproject.toml").is_file()
    assert (project / "src" / "recon" / "__init__.py").is_file()


def test_archive_download_falls_back_when_codeload_is_unavailable(
    monkeypatch, update_environment
):
    response = _tar_response({
        "osint-recon-revision/pyproject.toml": b"[project]\nname='osint-recon'\n",
    })
    urls: list[str] = []

    def open_archive(request, **_kwargs):
        urls.append(request.full_url)
        if len(urls) == 1:
            raise urllib.error.URLError("offline")
        return response

    monkeypatch.setattr(updater.urllib.request, "urlopen", open_archive)

    project = updater._download_revision(REVISION_A, 5)

    assert (project / "pyproject.toml").is_file()
    assert urls == [template.format(revision=REVISION_A) for template in updater.GITHUB_ARCHIVE_URLS]


def test_download_failure_explains_network_problem(monkeypatch, update_environment):
    monkeypatch.setattr(updater, "_installed_revision", lambda: REVISION_A)
    monkeypatch.setattr(
        updater,
        "_download_revision",
        lambda *_args: (_ for _ in ()).throw(urllib.error.URLError("offline")),
    )

    result = updater.download_build(REVISION_B)

    assert result.attempted and not result.downloaded
    assert "could not reach GitHub" in result.message
    assert "installed version was not changed" in result.message


def test_archive_download_rejects_path_traversal(monkeypatch, update_environment):
    response = _tar_response({
        "osint-recon-revision/../escape.txt": b"unsafe",
        "osint-recon-revision/pyproject.toml": b"[project]",
    })
    monkeypatch.setattr(updater.urllib.request, "urlopen", lambda *_args, **_kwargs: response)

    with pytest.raises(ValueError, match="unsafe path"):
        updater._download_revision(REVISION_A, 5)

    assert not (update_environment.parent / "escape.txt").exists()


def test_archive_download_rejects_oversized_response(monkeypatch, update_environment):
    response = _tar_response(
        {"osint-recon-revision/pyproject.toml": b"[project]"},
        size=str(updater._MAX_ARCHIVE_BYTES + 1),
    )
    monkeypatch.setattr(updater.urllib.request, "urlopen", lambda *_args, **_kwargs: response)

    with pytest.raises(ValueError, match="too large"):
        updater._download_revision(REVISION_A, 5)


def test_apply_uses_exact_cached_revision(monkeypatch, update_environment):
    project = _cached_project(update_environment, REVISION_B)
    monkeypatch.setattr(
        updater,
        "check_for_update",
        lambda **_kwargs: (_ for _ in ()).throw(AssertionError("replaced selected build")),
    )
    commands: list[list[str]] = []
    monkeypatch.setattr(
        updater.subprocess,
        "run",
        lambda command, **_kwargs: (
            commands.append(command) or subprocess.CompletedProcess(command, 0, "", "")
        ),
    )

    result = updater.apply_pending_update()

    assert result.applied
    assert commands == [[
        "uv", "tool", "install", "--force", "--reinstall-package", "osint-recon",
        "--quiet", "--no-progress", f"{project}[desktop]",
    ]]
    assert not (update_environment / "pending.json").exists()
    assert json.loads((update_environment / "installed.json").read_text())["revision"] == REVISION_B
    assert not project.exists()


def test_apply_preserves_pending_update_on_failure(monkeypatch, update_environment):
    _cached_project(update_environment, REVISION_B)
    monkeypatch.setattr(
        updater, "check_for_update", lambda **_kwargs: updater.UpdateResult(attempted=True)
    )
    monkeypatch.setattr(
        updater.subprocess,
        "run",
        lambda command, **_kwargs: subprocess.CompletedProcess(command, 1, "", "failed"),
    )

    result = updater.apply_pending_update()

    assert not result.applied and result.update_available
    assert (update_environment / "pending.json").exists()


def test_apply_can_use_cached_update_while_check_is_offline(monkeypatch, update_environment):
    _cached_project(update_environment, REVISION_B)
    monkeypatch.setattr(
        updater,
        "check_for_update",
        lambda **_kwargs: updater.UpdateResult(attempted=True, message="offline"),
    )
    monkeypatch.setattr(
        updater.subprocess,
        "run",
        lambda command, **_kwargs: subprocess.CompletedProcess(command, 0, "", ""),
    )

    assert updater.apply_pending_update().applied


def test_pipx_apply_command_uses_cached_project(tmp_path):
    assert updater._apply_command(("pipx", "pipx"), tmp_path) == [
        "pipx", "install", "--force", "--quiet", f"{tmp_path}[desktop]"
    ]


def test_update_status_reports_installed_and_downloaded_revisions(
    monkeypatch, update_environment
):
    _cached_project(update_environment, REVISION_B)
    monkeypatch.setattr(updater, "_installed_revision", lambda: REVISION_A)

    status = updater.get_update_status()

    assert status.supported
    assert status.installed_label == f"Build {REVISION_A[:12]}"
    assert status.pending_label == f"Build {REVISION_B[:12]}"
    assert not status.pending_selected


def test_monitor_checks_repeatedly_and_stops(monkeypatch, update_environment):
    calls: list[int] = []
    notices: list[str] = []

    def check():
        calls.append(1)
        return updater.UpdateResult(
            attempted=True,
            update_available=True,
            downloaded=len(calls) == 1,
            message="update ready",
        )

    monkeypatch.setattr(updater, "check_for_update", check)
    monitor = updater.start_update_monitor(interval=0.01, notify=notices.append)
    deadline = time.time() + 1
    while len(calls) < 2 and time.time() < deadline:
        time.sleep(0.005)
    monitor.stop()
    count_after_stop = len(calls)
    time.sleep(0.03)

    assert count_after_stop >= 2
    assert len(calls) == count_after_stop
    assert notices == ["update ready"]


def test_launcher_routes_research_commands_to_specter_cli(monkeypatch):
    from recon import cli, launch

    received: list[list[str]] = []
    monkeypatch.setattr(cli, "main", received.append)

    launch.main(["scan", "torvalds"])

    assert received == [["scan", "torvalds"]]


def test_launcher_routes_quality_and_diagnostic_commands_to_specter_cli(monkeypatch):
    from recon import cli, launch

    received: list[list[str]] = []
    monkeypatch.setattr(cli, "main", received.append)

    launch.main(["evaluate", "--json"])
    launch.main(["diagnostics", "--json"])

    assert received == [["evaluate", "--json"], ["diagnostics", "--json"]]


def test_launcher_exposes_the_platform_icon_path(capsys):
    from recon import launch

    launch.main(["--icon-path"])

    icon_path = Path(capsys.readouterr().out.strip())
    assert icon_path == launch._icon_path()
    assert icon_path.is_file()
    assert icon_path.suffix == (".ico" if os.name == "nt" else ".png")


def test_launcher_refuses_update_while_specter_is_running(monkeypatch, capsys):
    from recon import launch

    monkeypatch.setattr(launch, "_port_open", lambda host, port: True)
    monkeypatch.setattr(
        launch,
        "apply_pending_update",
        lambda: (_ for _ in ()).throw(AssertionError("updated a running installation")),
    )

    with pytest.raises(SystemExit) as raised:
        launch.main(["--update"])

    assert raised.value.code == 2
    assert "Stop the running Specter application" in capsys.readouterr().out


def test_manual_update_applies_and_exits(monkeypatch, capsys):
    from recon import launch

    monkeypatch.setattr(launch, "_port_open", lambda host, port: False)
    monkeypatch.setattr(
        launch,
        "apply_pending_update",
        lambda: updater.UpdateResult(attempted=True, applied=True, message="applied"),
    )

    with pytest.raises(SystemExit) as raised:
        launch.main(["--update"])

    assert raised.value.code == 0
    assert "applied" in capsys.readouterr().out


def test_launcher_prepares_server_then_workers_and_monitor(monkeypatch):
    from recon import launch

    events: list[str] = []

    class FinishedProcess:
        def poll(self):
            return 0

    class Monitor:
        def stop(self):
            events.append("monitor:stop")

    monkeypatch.setattr(launch, "_port_open", lambda host, port: False)
    monkeypatch.setattr(launch, "_prepare_database", lambda: events.append("database"))
    monkeypatch.setattr(
        launch,
        "_spawn",
        lambda args, **_kwargs: (events.append(f"spawn:{args[0]}") or FinishedProcess()),
    )
    monkeypatch.setattr(launch, "_wait_healthy", lambda url: (events.append("healthy") or True))
    monkeypatch.setattr(
        launch,
        "start_update_monitor",
        lambda **_kwargs: (events.append("monitor:start") or Monitor()),
    )
    monkeypatch.setattr(launch.signal, "signal", lambda *_args: None)
    monkeypatch.setattr(launch.time, "sleep", lambda _seconds: None)

    launch.main(["--no-browser"])

    assert events == [
        "database", "spawn:serve", "healthy", "spawn:worker", "spawn:monitor",
        "monitor:start", "monitor:stop",
    ]


def test_launcher_owns_desktop_services_until_window_closes(monkeypatch, tmp_path):
    from recon import launch

    events: list[str] = []

    class RunningProcess:
        def __init__(self, name):
            self.name = name
            self.running = True

        def poll(self):
            return None if self.running else 0

        def terminate(self):
            events.append(f"stop:{self.name}")
            self.running = False

        def wait(self, timeout):
            return 0

    monkeypatch.setattr(launch, "_port_open", lambda host, port: False)
    monkeypatch.setattr(launch, "_prepare_database", lambda: events.append("database"))
    monkeypatch.setattr(launch, "_wait_healthy", lambda url: True)
    monkeypatch.setattr(launch, "state_root", lambda: tmp_path)
    monkeypatch.setattr(
        launch,
        "_spawn",
        lambda args, **_kwargs: (
            events.append(f"start:{args[0]}") or RunningProcess(args[0])
        ),
    )
    monkeypatch.setattr(
        launch,
        "_run_desktop",
        lambda url, **_kwargs: (events.append(f"desktop:{url}") or "quit"),
    )

    launch.main([])

    assert events == [
        "database",
        "start:serve",
        "start:worker",
        "start:monitor",
        "desktop:http://127.0.0.1:8000",
        "stop:serve",
        "stop:worker",
        "stop:monitor",
    ]


def test_desktop_update_request_stops_services_applies_and_restarts(monkeypatch, tmp_path):
    from recon import launch

    events: list[str] = []

    class RunningProcess:
        running = True

        def poll(self):
            return None if self.running else 0

        def terminate(self):
            self.running = False
            events.append("stop")

        def wait(self, timeout):
            return 0

    monkeypatch.setattr(launch, "_port_open", lambda host, port: False)
    monkeypatch.setattr(launch, "_prepare_database", lambda: None)
    monkeypatch.setattr(launch, "_wait_healthy", lambda url: True)
    monkeypatch.setattr(launch, "state_root", lambda: tmp_path)
    monkeypatch.setattr(launch, "_spawn", lambda args, **_kwargs: RunningProcess())
    monkeypatch.setattr(launch, "_run_desktop", lambda url, **_kwargs: "apply-update")
    monkeypatch.setattr(
        launch,
        "apply_pending_update",
        lambda: (events.append("apply") or updater.UpdateResult(applied=True, message="updated")),
    )
    monkeypatch.setattr(
        launch,
        "_restart_application",
        lambda **kwargs: events.append(f"restart:{kwargs['notice']}"),
    )

    launch.main([])

    assert events == ["stop", "stop", "stop", "apply", "restart:updated"]


def test_desktop_log_rotates_before_startup(monkeypatch, tmp_path):
    from recon import launch

    log = tmp_path / "logs" / "specter.log"
    log.parent.mkdir(parents=True)
    with log.open("wb") as stream:
        stream.truncate(5 * 1024 * 1024)
    monkeypatch.setattr(launch, "state_root", lambda: tmp_path)

    assert launch._desktop_log_path() == log
    assert not log.exists()
    assert log.with_suffix(".log.1").stat().st_size == 5 * 1024 * 1024


def test_launcher_does_not_spawn_when_database_preparation_fails(monkeypatch, capsys):
    from recon import launch

    monkeypatch.setattr(launch, "_port_open", lambda host, port: False)
    monkeypatch.setattr(
        launch,
        "_prepare_database",
        lambda: (_ for _ in ()).throw(RuntimeError("migration unavailable")),
    )
    monkeypatch.setattr(
        launch,
        "_spawn",
        lambda args: (_ for _ in ()).throw(AssertionError("spawned after database failure")),
    )

    with pytest.raises(SystemExit) as raised:
        launch.main(["--no-browser"])

    assert raised.value.code == 1
    assert "could not prepare its local database: migration unavailable" in capsys.readouterr().err
