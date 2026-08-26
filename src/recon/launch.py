"""Specter application launcher and local service supervisor."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import signal
import shutil
import socket
import subprocess
import sys
import time
import urllib.request

from .config import SETTINGS
from .desktop_settings import load_desktop_settings, state_root
from .updater import apply_pending_update, start_update_monitor

BANNER = r"""
   ____                 _
  / ___| _ __  ___  ___| |_ ___ _ __
  \___ \| '_ \/ _ \/ __| __/ _ \ '__|
   ___) | |_) |  __/ (__| ||  __/ |
  |____/| .__/ \___|\___|\__\___|_|
        |_|   Specter
"""

CLI_COMMANDS = frozenset({
    "analytics", "calibrate", "changes", "db-check", "db-upgrade", "diagnostics",
    "decrypt-export", "evaluate", "export-target", "graph", "insights", "maturity",
    "ml-status", "ml-train", "monitor", "pair-review", "provenance",
    "purge-target", "retention", "review", "review-labels", "runs", "scan",
    "serve", "source-check", "source-pack", "sources", "targets", "user-add",
    "user-list", "user-update", "worker",
})


def _icon_path() -> Path:
    suffix = ".ico" if os.name == "nt" else ".png"
    return Path(__file__).with_name("assets") / f"specter{suffix}"


def _installed_tool_environment() -> bool:
    return Path(sys.prefix).name.casefold().replace("_", "-") == "osint-recon"


def _application_executable() -> Path | None:
    suffix = ".exe" if os.name == "nt" else ""
    candidates: list[str | None] = []
    if sys.argv and sys.argv[0]:
        invoked = Path(sys.argv[0]).expanduser()
        candidates.extend((str(invoked.with_name(f"specter-app{suffix}")), str(invoked)))
    candidates.append(shutil.which("specter-app"))
    candidates.append(str(Path.home() / ".local" / "bin" / f"specter-app{suffix}"))
    for candidate in candidates:
        if candidate:
            path = Path(candidate)
            if path.is_file() and path.name.casefold().startswith("specter-app"):
                return path.resolve()
    return None


def _refresh_platform_integration() -> None:
    icon = _icon_path()
    if not icon.is_file():
        return
    try:
        if os.name == "nt":
            appdata = os.environ.get("APPDATA")
            localappdata = os.environ.get("LOCALAPPDATA")
            system_root = os.environ.get("SystemRoot")
            executable = _application_executable()
            if not appdata or not localappdata or not system_root or executable is None:
                return
            powershell = (
                Path(system_root) / "System32" / "WindowsPowerShell" / "v1.0" / "powershell.exe"
            )
            if not powershell.is_file():
                return
            stable_icon = Path(localappdata) / "Specter" / "assets" / "specter.ico"
            stable_icon.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(icon, stable_icon)
            start_shortcut = (
                Path(appdata)
                / "Microsoft"
                / "Windows"
                / "Start Menu"
                / "Programs"
                / "Specter.lnk"
            )
            script = (
                "$w=New-Object -ComObject WScript.Shell;"
                "$d=[Environment]::GetFolderPath("
                "[Environment+SpecialFolder]::DesktopDirectory);"
                "$paths=@($env:SPECTER_START_SHORTCUT,(Join-Path $d 'Specter.lnk'));"
                "foreach($p in $paths){$s=$w.CreateShortcut($p);"
                "$s.TargetPath=$env:SPECTER_APP_PATH;"
                "$s.WorkingDirectory=$env:SPECTER_WORKING_DIRECTORY;"
                "$s.Description='Specter research and evidence workspace';"
                "$s.IconLocation=$env:SPECTER_ICON_PATH+',0';$s.Save()}"
            )
            environment = os.environ.copy()
            environment["SPECTER_START_SHORTCUT"] = str(start_shortcut)
            environment["SPECTER_APP_PATH"] = str(executable)
            environment["SPECTER_WORKING_DIRECTORY"] = str(Path.home())
            environment["SPECTER_ICON_PATH"] = str(stable_icon)
            subprocess.run(
                [
                    str(powershell), "-NoProfile", "-NonInteractive",
                    "-WindowStyle", "Hidden", "-Command", script,
                ],
                check=False,
                capture_output=True,
                timeout=5,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
                env=environment,
            )
            return

        data_home = Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share"))
        desktop_entry = data_home / "applications" / "specter.desktop"
        if not desktop_entry.is_file():
            return
        destination = data_home / "icons" / "hicolor" / "512x512" / "apps" / "specter.png"
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(icon, destination)
    except (OSError, subprocess.SubprocessError):
        return


def _output(message: str, *, error: bool = False) -> None:
    stream = sys.stderr if error else sys.stdout
    if stream is not None:
        print(message, file=stream)


def _port_open(host: str, port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as connection:
        connection.settimeout(0.5)
        return connection.connect_ex((host, port)) == 0


def _wait_healthy(url: str, timeout: float = 25.0) -> bool:
    deadline = time.time() + timeout
    health_url = f"{url.rstrip('/')}/health/live"
    while time.time() < deadline:
        try:
            # The caller constructs this URL from the fixed loopback host.
            with urllib.request.urlopen(health_url, timeout=2) as response:  # nosec B310
                payload = json.loads(response.read(16 * 1024))
                if response.status == 200 and payload.get("status") == "alive":
                    return True
        except (OSError, ValueError, json.JSONDecodeError):
            time.sleep(0.4)
    return False


def _spawn(args: list[str], *, log_path: Path | None = None) -> subprocess.Popen:
    command = [sys.executable, "-m", "recon.cli", *args]
    if log_path is None:
        return subprocess.Popen(command)  # nosec B603
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with log_path.open("a", encoding="utf-8") as log:
        return subprocess.Popen(  # nosec B603
            command,
            stdin=subprocess.DEVNULL,
            stdout=log,
            stderr=subprocess.STDOUT,
        )


def _desktop_log_path() -> Path:
    log_path = state_root() / "logs" / "specter.log"
    try:
        if log_path.stat().st_size >= 5 * 1024 * 1024:
            backup = log_path.with_suffix(".log.1")
            backup.unlink(missing_ok=True)
            log_path.replace(backup)
    except OSError:
        pass
    return log_path


def _prepare_database() -> None:
    from .store.db import Database, _default_dsn

    with Database(_default_dsn()) as database:
        database.ensure_schema(auto_upgrade=SETTINGS.auto_migrate)
        database.ping()


def _run_desktop(url: str, *, updates: bool, instance_key: str) -> str:
    try:
        from .desktop import run_desktop
    except ImportError as exc:
        if exc.name and exc.name.startswith("PySide6"):
            _output(
                "Specter's desktop components are missing. Re-run the one-command installer.",
                error=True,
            )
            raise SystemExit(1) from None
        raise
    return run_desktop(url, update_checks_allowed=updates, instance_key=instance_key)


def _shutdown_processes(processes: list[subprocess.Popen]) -> None:
    running = [process for process in processes if process.poll() is None]
    for process in running:
        process.terminate()
    for process in running:
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=2)


def _restart_application(*, notice: str = "") -> None:
    environment = os.environ.copy()
    if notice:
        environment["SPECTER_STARTUP_NOTICE"] = notice
    options: dict = {
        "stdin": subprocess.DEVNULL,
        "stdout": subprocess.DEVNULL,
        "stderr": subprocess.DEVNULL,
        "env": environment,
    }
    if os.name == "nt":
        options["creationflags"] = (
            subprocess.CREATE_NEW_PROCESS_GROUP | subprocess.DETACHED_PROCESS
        )
    else:
        options["start_new_session"] = True
    subprocess.Popen([sys.executable, "-m", "recon.launch"], **options)  # nosec B603


def _run_headless(processes: list[subprocess.Popen], *, updates: bool) -> None:
    monitor = start_update_monitor(
        enabled=updates,
        notify=lambda message: _output(f"\n  {message}"),
    )
    if not updates:
        _output("  update checks disabled")
    elif monitor is not None:
        _output("  checking GitHub for updates every 5 minutes")
    _output("  services running - press Ctrl-C to shut down")

    stopping = False

    def request_shutdown(*_args) -> None:
        nonlocal stopping
        stopping = True

    signal.signal(signal.SIGINT, request_shutdown)
    signal.signal(signal.SIGTERM, request_shutdown)
    try:
        while not stopping and not all(process.poll() is not None for process in processes):
            time.sleep(1)
    finally:
        if monitor is not None:
            monitor.stop()


def main(argv: list[str] | None = None) -> None:
    launch_args = list(sys.argv[1:] if argv is None else argv)
    if launch_args and launch_args[0] in CLI_COMMANDS:
        from .cli import main as cli_main

        cli_main(launch_args)
        return

    parser = argparse.ArgumentParser(
        prog="specter",
        description="Start the Specter desktop application.",
        epilog="Research commands remain available, for example: specter scan <value>",
    )
    parser.add_argument(
        "--headless", action="store_true", help="run local services without the desktop window"
    )
    parser.add_argument("--no-browser", dest="headless", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--no-workers", action="store_true", help="don't start background services")
    update_mode = parser.add_mutually_exclusive_group()
    update_mode.add_argument("--no-update", action="store_true", help="disable update checks")
    update_mode.add_argument(
        "--update", action="store_true", help="apply the downloaded update and exit"
    )
    parser.add_argument("--icon-path", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--port", type=int, default=SETTINGS.port)
    args = parser.parse_args(launch_args)

    if args.icon_path:
        _output(str(_icon_path()))
        return

    if not args.headless and not args.update and _installed_tool_environment():
        _refresh_platform_integration()

    host, port = SETTINGS.host, args.port
    url = f"http://{host}:{port}"
    updates_enabled = not args.no_update

    if args.headless:
        _output(BANNER)

    if args.update:
        if _port_open(host, port):
            _output("Stop the running Specter application before applying its update.")
            raise SystemExit(2)
        update = apply_pending_update()
        _output(update.message or "No update is available.")
        raise SystemExit(0 if update.applied or not update.update_available else 1)

    if _port_open(host, port):
        if not _wait_healthy(url, timeout=2):
            _output(f"Port {port} is already used by another application.", error=True)
            raise SystemExit(1)
        if args.headless:
            _output(f"  Specter is already running at {url}")
            return
        _run_desktop(url, updates=updates_enabled, instance_key=f"{host}:{port}")
        return

    try:
        _prepare_database()
    except Exception as exc:
        _output(f"Specter could not prepare its local database: {exc}", error=True)
        raise SystemExit(1) from None

    desktop_settings = load_desktop_settings()
    if "RECON_MAIGRET_ENABLED" not in os.environ:
        os.environ["RECON_MAIGRET_ENABLED"] = (
            "true" if desktop_settings.maigret_enabled else "false"
        )
    start_workers = not args.no_workers and (
        args.headless or desktop_settings.background_services
    )
    log_path = None if args.headless else _desktop_log_path()
    processes: list[subprocess.Popen] = [_spawn(["serve"], log_path=log_path)]

    if not _wait_healthy(url):
        _output("Specter's local service did not become ready. Check the application log.", error=True)
        _shutdown_processes(processes)
        raise SystemExit(1)

    if start_workers:
        processes.append(_spawn(["worker"], log_path=log_path))
        processes.append(_spawn(["monitor"], log_path=log_path))

    action = "quit"
    try:
        if args.headless:
            _run_headless(processes, updates=updates_enabled)
        else:
            action = _run_desktop(
                url,
                updates=updates_enabled,
                instance_key=f"{host}:{port}",
            )
    finally:
        _shutdown_processes(processes)

    if action == "apply-update":
        result = apply_pending_update()
        _restart_application(notice=result.message)


if __name__ == "__main__":
    main()
