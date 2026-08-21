"""Minimal native desktop smoke check used by CI and release validation."""

from __future__ import annotations

import argparse

from PySide6.QtCore import QTimer
from PySide6.QtWidgets import QApplication

from recon.desktop import SettingsDialog, SpecterWindow, UpdateDialog
from recon.desktop_settings import DesktopSettings
from recon.updater import AvailableBuild, UpdateStatus


def main(*, verify_javascript_bridge: bool = True) -> None:
    app = QApplication.instance() or QApplication([])
    settings = DesktopSettings(
        check_for_updates=False,
        notifications=False,
        close_to_tray=False,
    )
    window = SpecterWindow(
        "about:blank",
        settings,
        update_checks_allowed=False,
        instance_name="specter-ci-desktop-smoke",
    )
    settings_dialog = SettingsDialog(settings, window)
    update_dialog = UpdateDialog(
        UpdateStatus(False, None, None),
        check_now=lambda: None,
        load_history=lambda: None,
        select_build=lambda _build: None,
        apply_update=lambda: None,
        parent=window,
    )
    update_dialog.set_history(
        [AvailableBuild("a" * 40, "Desktop smoke build", "2026-08-21T09:30:00Z")]
    )
    notifications: list[tuple[str, str, str]] = []

    def record_notification(title: str, message: str, level: str) -> None:
        notifications.append((title, message, level))
        app.quit()

    window.bridge.notification.connect(record_notification)

    menus = {action.text().replace("&", "") for action in window.menuBar().actions()}
    if menus != {"File", "Navigate", "View", "Tools", "Help"}:
        raise RuntimeError(f"unexpected desktop menus: {sorted(menus)}")
    if settings_dialog.windowTitle() != "Specter Settings":
        raise RuntimeError("settings dialog did not initialize")
    if update_dialog.windowTitle() != "Specter Updates" or update_dialog.apply_button.isEnabled():
        raise RuntimeError("update manager did not initialize")
    if update_dialog.history.rowCount() != 1:
        raise RuntimeError("version history did not initialize")
    if window.windowTitle() != "Specter":
        raise RuntimeError("desktop window did not initialize")

    def dispatch_when_ready(ready: object) -> None:
        if bool(ready):
            window.view.page().runJavaScript(
                "window.dispatchEvent(new CustomEvent('specter:notification',"
                "{detail:{title:'Bridge',message:'ready',level:'info'}}))"
            )
            return
        QTimer.singleShot(100, poll_bridge)

    def poll_bridge() -> None:
        window.view.page().runJavaScript(
            "Boolean(window.__specterDesktopBridgeReady)",
            dispatch_when_ready,
        )

    def renderer_ready(html: str) -> None:
        if "Specter desktop smoke" in html:
            window.bridge.notify("Bridge", "ready", "info")
            return
        QTimer.singleShot(100, poll_renderer)

    def poll_renderer() -> None:
        window.view.page().toHtml(renderer_ready)

    window.view.stop()
    window.view.setHtml("<html><head></head><body>Specter desktop smoke</body></html>")
    window.show()
    QTimer.singleShot(0, poll_bridge if verify_javascript_bridge else poll_renderer)
    QTimer.singleShot(10_000, app.quit)
    app.exec()
    window.shutdown()
    if notifications != [("Bridge", "ready", "info")]:
        raise RuntimeError(f"native notification bridge failed: {notifications}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--renderer-only",
        action="store_true",
        help="verify the embedded renderer and native signal path without WebChannel",
    )
    arguments = parser.parse_args()
    main(verify_javascript_bridge=not arguments.renderer_only)
