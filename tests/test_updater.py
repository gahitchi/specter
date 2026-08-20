from __future__ import annotations

import subprocess

import pytest

from recon import updater


def test_auto_update_can_be_disabled(monkeypatch):
    monkeypatch.setenv("RECON_AUTO_UPDATE", "0")
    monkeypatch.setattr(updater, "_update_command", lambda: (_ for _ in ()).throw(AssertionError))

    result = updater.auto_update()

    assert not result.attempted
    assert not result.restart_required


def test_forced_update_overrides_disabled_automatic_checks(monkeypatch):
    monkeypatch.setenv("RECON_AUTO_UPDATE", "0")
    monkeypatch.setattr(
        updater,
        "_update_command",
        lambda: (["uv", "tool", "upgrade"], "uv"),
    )
    monkeypatch.setattr(updater, "_installation_fingerprint", lambda: ("0.11.0", None))
    monkeypatch.setattr(
        updater.subprocess,
        "run",
        lambda *args, **kwargs: subprocess.CompletedProcess(args[0], 0, "", ""),
    )

    result = updater.auto_update(force=True)

    assert result.attempted
    assert result.message == "application is up to date"


def test_auto_update_skips_development_checkout(monkeypatch):
    monkeypatch.delenv("RECON_AUTO_UPDATE", raising=False)
    monkeypatch.setattr(updater, "_update_command", lambda: None)

    result = updater.auto_update()

    assert not result.attempted
    assert not result.restart_required


def test_auto_update_skips_production_runtime(monkeypatch):
    monkeypatch.setenv("RECON_ENV", "production")
    monkeypatch.setattr(updater, "_update_command", lambda: (_ for _ in ()).throw(AssertionError))

    result = updater.auto_update()

    assert not result.attempted
    assert not result.restart_required


def test_update_command_uses_uv_for_its_own_tool_environment(monkeypatch, tmp_path):
    tool_dir = tmp_path / "tools"
    environment = tool_dir / "osint-recon"
    monkeypatch.setattr(updater.sys, "prefix", str(environment))
    monkeypatch.setattr(updater.shutil, "which", lambda name: "uv" if name == "uv" else None)
    monkeypatch.setattr(updater, "_command_output", lambda command: str(tool_dir))

    command = updater._update_command()

    assert command == (
        [
            "uv",
            "tool",
            "upgrade",
            "osint-recon",
            "--reinstall-package",
            "osint-recon",
            "--quiet",
            "--no-progress",
        ],
        "uv",
    )


def test_auto_update_continues_when_manager_fails(monkeypatch):
    monkeypatch.delenv("RECON_AUTO_UPDATE", raising=False)
    monkeypatch.setattr(updater, "_update_command", lambda: (["uv", "tool", "upgrade"], "uv"))
    monkeypatch.setattr(updater, "_installation_fingerprint", lambda: ("0.11.0", "a" * 40))
    monkeypatch.setattr(
        updater.subprocess,
        "run",
        lambda *args, **kwargs: subprocess.CompletedProcess(args[0], 1, "", "offline"),
    )

    result = updater.auto_update()

    assert result.attempted
    assert not result.restart_required
    assert "installed version" in result.message


def test_auto_update_requests_restart_for_new_revision(monkeypatch):
    monkeypatch.delenv("RECON_AUTO_UPDATE", raising=False)
    monkeypatch.setattr(updater, "_update_command", lambda: (["uv", "tool", "upgrade"], "uv"))
    fingerprints = iter([("0.11.0", "a" * 40), ("0.11.0", "b" * 40)])
    monkeypatch.setattr(updater, "_installation_fingerprint", lambda: next(fingerprints))
    monkeypatch.setattr(
        updater.subprocess,
        "run",
        lambda *args, **kwargs: subprocess.CompletedProcess(args[0], 0, "", ""),
    )

    result = updater.auto_update()

    assert result.attempted
    assert result.restart_required
    assert "aaaaaaaa -> bbbbbbbb" in result.message


def test_auto_update_does_not_restart_when_current(monkeypatch):
    monkeypatch.delenv("RECON_AUTO_UPDATE", raising=False)
    monkeypatch.setattr(updater, "_update_command", lambda: (["pipx", "upgrade"], "pipx"))
    monkeypatch.setattr(updater, "_installation_fingerprint", lambda: ("0.11.0", None))
    monkeypatch.setattr(
        updater.subprocess,
        "run",
        lambda *args, **kwargs: subprocess.CompletedProcess(args[0], 0, "", ""),
    )

    result = updater.auto_update()

    assert result.attempted
    assert not result.restart_required
    assert result.message == "application is up to date"


def test_launcher_restarts_updated_code_before_spawning_children(monkeypatch):
    from recon import launch

    restarted: list[list[str]] = []
    monkeypatch.setattr(launch, "_port_open", lambda host, port: False)
    monkeypatch.setattr(
        launch,
        "auto_update",
        lambda *, enabled, force=False: updater.UpdateResult(True, True, "updated"),
    )
    monkeypatch.setattr(
        launch,
        "_spawn",
        lambda args: (_ for _ in ()).throw(AssertionError("spawned before restart")),
    )

    def fake_restart(argv):
        restarted.append(argv)
        raise RuntimeError("restart requested")

    monkeypatch.setattr(launch, "restart", fake_restart)

    with pytest.raises(RuntimeError, match="restart requested"):
        launch.main(["--no-browser", "--no-workers"])

    assert restarted == [["--no-browser", "--no-workers"]]


def test_manual_update_exits_without_starting_services(monkeypatch, capsys):
    from recon import launch

    calls: list[tuple[bool, bool]] = []
    monkeypatch.setattr(launch, "_port_open", lambda host, port: False)
    monkeypatch.setattr(
        launch,
        "auto_update",
        lambda *, enabled, force=False: (
            calls.append((enabled, force))
            or updater.UpdateResult(True, True, "updated with uv: old -> new")
        ),
    )
    monkeypatch.setattr(
        launch,
        "_prepare_database",
        lambda: (_ for _ in ()).throw(AssertionError("database prepared during update")),
    )
    monkeypatch.setattr(
        launch,
        "_spawn",
        lambda args: (_ for _ in ()).throw(AssertionError("service started during update")),
    )

    launch.main(["--update"])

    assert calls == [(True, True)]
    assert "updated with uv: old -> new" in capsys.readouterr().out


def test_launcher_prepares_database_and_server_before_workers(monkeypatch):
    from recon import launch

    events: list[str] = []

    class FinishedProcess:
        def poll(self):
            return 0

    monkeypatch.setattr(launch, "_port_open", lambda host, port: False)
    monkeypatch.setattr(
        launch,
        "auto_update",
        lambda *, enabled, force=False: updater.UpdateResult(),
    )
    monkeypatch.setattr(
        launch,
        "_prepare_database",
        lambda: events.append("database"),
    )
    monkeypatch.setattr(
        launch,
        "_spawn",
        lambda args: (events.append(f"spawn:{args[0]}") or FinishedProcess()),
    )
    monkeypatch.setattr(
        launch,
        "_wait_healthy",
        lambda url: (events.append("healthy") or True),
    )
    monkeypatch.setattr(launch.signal, "signal", lambda *_args: None)
    monkeypatch.setattr(launch.time, "sleep", lambda _seconds: None)

    launch.main(["--no-browser"])

    assert events == [
        "database",
        "spawn:serve",
        "healthy",
        "spawn:worker",
        "spawn:monitor",
    ]


def test_launcher_does_not_spawn_when_database_preparation_fails(monkeypatch, capsys):
    from recon import launch

    monkeypatch.setattr(launch, "_port_open", lambda host, port: False)
    monkeypatch.setattr(
        launch,
        "auto_update",
        lambda *, enabled, force=False: updater.UpdateResult(),
    )
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
    assert "database startup failed: migration unavailable" in capsys.readouterr().err


def test_restart_sets_guard_and_preserves_arguments(monkeypatch):
    executed: dict[str, object] = {}

    def fake_execve(executable, arguments, environment):
        executed.update(
            executable=executable,
            arguments=arguments,
            environment=environment,
        )
        raise RuntimeError("process replaced")

    monkeypatch.setattr(updater.os, "execve", fake_execve)

    with pytest.raises(RuntimeError, match="process replaced"):
        updater.restart(["--no-browser"])

    assert executed["executable"] == updater.sys.executable
    assert executed["arguments"] == [
        updater.sys.executable,
        "-m",
        "recon.launch",
        "--no-browser",
    ]
    assert executed["environment"]["RECON_UPDATE_RESTARTED"] == "1"
