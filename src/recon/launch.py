"""Specter launcher: wake the whole stack and open the dashboard in Firefox.

Boots the API/dashboard server plus a background worker and the monitoring
scheduler, waits until the server is healthy, then opens a Firefox tab pointed at
the local dashboard. Stays in the foreground supervising the children; Ctrl-C
shuts everything down cleanly. If the server is already running it just opens the
tab and exits (the software is already awake).
"""

from __future__ import annotations

import argparse
import shutil
import signal
import socket
import subprocess
import sys
import time
import urllib.request
import webbrowser

from .config import SETTINGS
from .updater import apply_pending_update, start_update_monitor

BANNER = r"""
   ____                 _
  / ___| _ __  ___  ___| |_ ___ _ __
  \___ \| '_ \/ _ \/ __| __/ _ \ '__|
   ___) | |_) |  __/ (__| ||  __/ |
  |____/| .__/ \___|\___|\__\___|_|
        |_|   Specter - waking up...
"""

CLI_COMMANDS = frozenset({
    "analytics", "calibrate", "changes", "db-check", "db-upgrade",
    "decrypt-export", "export-target", "graph", "insights", "maturity",
    "ml-status", "ml-train", "monitor", "pair-review", "provenance",
    "purge-target", "retention", "review", "review-labels", "runs", "scan",
    "serve", "source-check", "source-pack", "sources", "targets", "user-add",
    "user-list", "user-update", "worker",
})


def _port_open(host: str, port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.5)
        return s.connect_ex((host, port)) == 0


def _wait_healthy(url: str, timeout: float = 25.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            # The caller constructs this URL from the fixed loopback host.
            with urllib.request.urlopen(url, timeout=2) as r:  # nosec B310
                if r.status == 200:
                    return True
        except Exception:
            time.sleep(0.4)
    return False


def open_firefox(url: str) -> None:
    """Open `url` in a new Firefox tab; fall back to the default browser."""
    firefox = shutil.which("firefox") or shutil.which("firefox-esr")
    if firefox:
        try:
            subprocess.Popen([firefox, "--new-tab", url],
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)  # nosec B603
            return
        except OSError:
            pass
    try:
        webbrowser.get("firefox").open_new_tab(url)
    except webbrowser.Error:
        webbrowser.open_new_tab(url)


def _spawn(args: list[str]) -> subprocess.Popen:
    return subprocess.Popen([sys.executable, "-m", "recon.cli", *args])  # nosec B603


def _prepare_database() -> None:
    from .store.db import Database, _default_dsn

    with Database(_default_dsn()) as database:
        database.ensure_schema(auto_upgrade=SETTINGS.auto_migrate)
        database.ping()


def main(argv: list[str] | None = None) -> None:
    launch_args = list(sys.argv[1:] if argv is None else argv)
    if launch_args and launch_args[0] in CLI_COMMANDS:
        from .cli import main as cli_main

        cli_main(launch_args)
        return

    p = argparse.ArgumentParser(
        prog="specter",
        description="Start Specter and open its dashboard.",
        epilog="Research commands are also available, for example: specter scan <value>",
    )
    p.add_argument("--no-browser", action="store_true", help="don't open Firefox")
    p.add_argument("--no-workers", action="store_true", help="server only (no worker/scheduler)")
    update_mode = p.add_mutually_exclusive_group()
    update_mode.add_argument("--no-update", action="store_true", help="disable update checks")
    update_mode.add_argument(
        "--update", action="store_true", help="apply the downloaded update and exit"
    )
    p.add_argument("--port", type=int, default=SETTINGS.port)
    args = p.parse_args(launch_args)

    host, port = SETTINGS.host, args.port
    url = f"http://{host}:{port}"

    print(BANNER)

    if args.update:
        if _port_open(host, port):
            print("  stop the running Specter instance before applying its update")
            raise SystemExit(2)
        update = apply_pending_update()
        print(f"  {update.message or 'no update is available'}")
        raise SystemExit(0 if update.applied or not update.update_available else 1)

    # Already awake? Just open the tab.
    if _port_open(host, port):
        print(f"  already running at {url}")
        if not args.no_browser:
            open_firefox(url)
        return

    try:
        _prepare_database()
    except Exception as exc:
        print(f"  database startup failed: {exc}", file=sys.stderr)
        raise SystemExit(1) from None

    procs: list[subprocess.Popen] = [_spawn(["serve"])]

    if _wait_healthy(url):
        print(f"  dashboard ready at {url}")
        if not args.no_workers:
            procs.append(_spawn(["worker"]))
            procs.append(_spawn(["monitor"]))
        if not args.no_browser:
            open_firefox(url)
            print("  opened Firefox tab")
    else:
        print("  server did not become healthy in time; check logs", file=sys.stderr)

    update_monitor = start_update_monitor(
        enabled=not args.no_update,
        notify=lambda message: print(f"\n  {message}"),
    )
    if args.no_update:
        print("  update checks disabled")
    elif update_monitor is not None:
        print("  checking GitHub for updates every 5 minutes")

    print("  stack running - press Ctrl-C to shut down")

    def _shutdown(*_):
        if update_monitor is not None:
            update_monitor.stop()
        for proc in procs:
            proc.terminate()
        for proc in procs:
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
        sys.exit(0)

    signal.signal(signal.SIGINT, _shutdown)
    signal.signal(signal.SIGTERM, _shutdown)
    while True:
        time.sleep(1)
        if all(proc.poll() is not None for proc in procs):
            break
    if update_monitor is not None:
        update_monitor.stop()


if __name__ == "__main__":
    main()
