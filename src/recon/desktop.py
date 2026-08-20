"""Native Specter desktop shell for the local investigation workspace."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import threading
from typing import Callable

from PySide6.QtCore import Qt, QTimer, QUrl, Signal, Slot
from PySide6.QtGui import QAction, QCloseEvent, QDesktopServices, QIcon, QKeySequence
from PySide6.QtNetwork import QLocalServer, QLocalSocket
from PySide6.QtWebChannel import QWebChannel
from PySide6.QtWebEngineCore import QWebEnginePage
from PySide6.QtWebEngineWidgets import QWebEngineView
from PySide6.QtWidgets import (
    QApplication,
    QAbstractItemView,
    QCheckBox,
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QGroupBox,
    QHeaderView,
    QHBoxLayout,
    QLabel,
    QMainWindow,
    QMenu,
    QMessageBox,
    QPushButton,
    QSpinBox,
    QStyle,
    QSystemTrayIcon,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from . import __version__
from .desktop_settings import (
    DesktopSettings,
    data_root,
    load_desktop_settings,
    save_desktop_settings,
    state_root,
)
from .updater import (
    AvailableBuild,
    UpdateResult,
    UpdateStatus,
    check_for_update,
    download_build,
    get_update_status,
    list_available_builds,
    start_update_monitor,
)

APPLY_UPDATE_EXIT_CODE = 42

_BRIDGE_SCRIPT = r"""
(() => {
  if (window.__specterDesktopBridgeInstalled) return;
  window.__specterDesktopBridgeInstalled = true;
  const script = document.createElement("script");
  script.src = "qrc:///qtwebchannel/qwebchannel.js";
  script.onload = () => {
    new QWebChannel(qt.webChannelTransport, (channel) => {
      const bridge = channel.objects.specterDesktop;
      window.addEventListener("specter:notification", (event) => {
        const detail = event.detail || {};
        bridge.notify(
          String(detail.title || "Specter"),
          String(detail.message || ""),
          String(detail.level || "info")
        );
      });
      window.__specterDesktopBridgeReady = true;
      window.dispatchEvent(new CustomEvent("specter:bridge-ready"));
    });
  };
  script.onerror = () => {
    window.__specterDesktopBridgeInstalled = false;
  };
  document.head.appendChild(script);
})();
"""

_APP_STYLESHEET = """
QMainWindow, QDialog { background: #171a18; color: #e7ebe8; }
QMenuBar { background: #1f2321; color: #e7ebe8; border-bottom: 1px solid #353a37; }
QMenuBar::item:selected, QMenu::item:selected { background: #2f5040; }
QMenu { background: #202421; color: #e7ebe8; border: 1px solid #414743; }
QStatusBar { background: #1f2321; color: #bec5c0; border-top: 1px solid #353a37; }
QGroupBox { border: 1px solid #414743; margin-top: 12px; padding: 14px 10px 10px; }
QGroupBox::title { subcontrol-origin: margin; left: 8px; padding: 0 5px; }
QLabel { color: #e7ebe8; }
QCheckBox, QSpinBox { color: #e7ebe8; }
QSpinBox { background: #222724; border: 1px solid #4a514d; padding: 5px; }
QPushButton { background: #2a302d; color: #edf1ee; border: 1px solid #4b544f; padding: 7px 12px; }
QPushButton:hover { background: #343b37; }
QPushButton:default { background: #2f6b4d; border-color: #78d6a8; }
QPushButton:disabled { color: #777e79; background: #202421; }
QTableWidget { background: #1b1f1d; color: #e7ebe8; border: 1px solid #414743; gridline-color: #353a37; }
QTableWidget::item { padding: 7px; }
QTableWidget::item:selected { background: #2f5040; }
QHeaderView::section { background: #252a27; color: #bec5c0; border: 0; border-right: 1px solid #414743; padding: 7px; }
"""


def _icon_path() -> Path:
    return Path(__file__).with_name("assets") / "specter.png"


def _instance_name(instance_key: str) -> str:
    identity = f"{Path.home().resolve()}:{instance_key}".encode("utf-8", errors="replace")
    return f"specter-{hashlib.sha256(identity).hexdigest()[:16]}"


class DesktopBridge(QWidget):
    notification = Signal(str, str, str)

    @Slot(str, str, str)
    def notify(self, title: str, message: str, level: str = "info") -> None:
        self.notification.emit(title, message, level)


class ExternalPage(QWebEnginePage):
    """Send links opened in a new window to the operating system browser."""

    def acceptNavigationRequest(self, url: QUrl, navigation_type, is_main_frame: bool) -> bool:
        if url.isValid() and url.scheme() in {"http", "https", "mailto"}:
            QDesktopServices.openUrl(url)
        self.deleteLater()
        return False


class SpecterPage(QWebEnginePage):
    def __init__(self, application_url: QUrl, parent: QWidget | None = None):
        super().__init__(parent)
        self._host = application_url.host()
        self._port = application_url.port()

    def acceptNavigationRequest(self, url: QUrl, navigation_type, is_main_frame: bool) -> bool:
        local = url.host() == self._host and url.port() == self._port
        if is_main_frame and url.scheme() in {"http", "https"} and not local:
            QDesktopServices.openUrl(url)
            return False
        return super().acceptNavigationRequest(url, navigation_type, is_main_frame)

    def createWindow(self, window_type) -> QWebEnginePage:
        return ExternalPage(self)


class SettingsDialog(QDialog):
    settings_saved = Signal(object)

    def __init__(self, settings: DesktopSettings, parent: QWidget | None = None):
        super().__init__(parent)
        self._settings = settings
        self.setWindowTitle("Specter Settings")
        self.setMinimumWidth(480)

        self.update_checks = QCheckBox("Check for updates every five minutes")
        self.update_checks.setChecked(settings.check_for_updates)
        self.notifications = QCheckBox("Show system notifications")
        self.notifications.setChecked(settings.notifications)
        self.close_to_tray = QCheckBox("Keep Specter running when the window closes")
        self.close_to_tray.setChecked(settings.close_to_tray)
        self.background_services = QCheckBox("Start research worker and monitor with Specter")
        self.background_services.setChecked(settings.background_services)
        self.zoom = QSpinBox()
        self.zoom.setRange(75, 175)
        self.zoom.setSingleStep(5)
        self.zoom.setSuffix(" %")
        self.zoom.setValue(settings.zoom_percent)

        general = QGroupBox("General")
        general_layout = QVBoxLayout(general)
        general_layout.addWidget(self.notifications)
        general_layout.addWidget(self.close_to_tray)
        general_layout.addWidget(self.background_services)

        appearance = QGroupBox("Workspace")
        appearance_layout = QFormLayout(appearance)
        appearance_layout.addRow("Page zoom", self.zoom)

        updates = QGroupBox("Updates")
        updates_layout = QVBoxLayout(updates)
        updates_layout.addWidget(self.update_checks)

        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Save | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(self._save)
        buttons.rejected.connect(self.reject)

        layout = QVBoxLayout(self)
        layout.addWidget(general)
        layout.addWidget(appearance)
        layout.addWidget(updates)
        layout.addWidget(buttons)

    def _save(self) -> None:
        updated = DesktopSettings(
            check_for_updates=self.update_checks.isChecked(),
            notifications=self.notifications.isChecked(),
            close_to_tray=self.close_to_tray.isChecked(),
            background_services=self.background_services.isChecked(),
            zoom_percent=self.zoom.value(),
            window_width=self._settings.window_width,
            window_height=self._settings.window_height,
            maximized=self._settings.maximized,
        )
        self.settings_saved.emit(updated)
        self.accept()


class UpdateDialog(QDialog):
    def __init__(
        self,
        status: UpdateStatus,
        check_now: Callable[[], None],
        load_history: Callable[[], None],
        select_build: Callable[[AvailableBuild], None],
        apply_update: Callable[[], None],
        parent: QWidget | None = None,
    ):
        super().__init__(parent)
        self._status = status
        self._check_now = check_now
        self._load_history = load_history
        self._select_build = select_build
        self._apply_update = apply_update
        self._builds: list[AvailableBuild] = []
        self.setWindowTitle("Specter Updates")
        self.setMinimumSize(760, 540)

        heading = QLabel("Version history")
        heading.setStyleSheet("font-size: 20px; font-weight: 600;")
        self.summary = QLabel()
        self.summary.setWordWrap(True)
        self.installed = QLabel()
        self.pending = QLabel()

        details = QGroupBox("Build information")
        details_layout = QFormLayout(details)
        details_layout.addRow("Application version", QLabel(__version__))
        details_layout.addRow("Installed build", self.installed)
        details_layout.addRow("Downloaded build", self.pending)

        history_header = QHBoxLayout()
        history_label = QLabel("Available builds")
        history_label.setStyleSheet("font-size: 14px; font-weight: 600;")
        self.history_status = QLabel("Open this window to load recent builds from GitHub.")
        self.history_status.setWordWrap(True)
        self.history_button = QPushButton("Refresh History")
        self.history_button.clicked.connect(self._request_history)
        history_header.addWidget(history_label)
        history_header.addStretch()
        history_header.addWidget(self.history_button)

        self.history = QTableWidget(0, 4)
        self.history.setHorizontalHeaderLabels(["Build", "Published", "Build ID", "Status"])
        self.history.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.history.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.history.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.history.setAlternatingRowColors(True)
        self.history.verticalHeader().setVisible(False)
        self.history.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        for column in (1, 2, 3):
            self.history.horizontalHeader().setSectionResizeMode(
                column, QHeaderView.ResizeMode.ResizeToContents
            )
        self.history.itemSelectionChanged.connect(self._selection_changed)

        self.check_button = QPushButton("Check Latest")
        self.check_button.clicked.connect(self._request_check)
        self.download_button = QPushButton("Download Selected")
        self.download_button.setEnabled(False)
        self.download_button.clicked.connect(self._request_download)
        self.apply_button = QPushButton("Install and Restart")
        self.apply_button.setDefault(True)
        self.apply_button.clicked.connect(self._apply_update)
        close_button = QPushButton("Close")
        close_button.clicked.connect(self.accept)

        actions = QHBoxLayout()
        actions.addWidget(self.check_button)
        actions.addWidget(self.download_button)
        actions.addStretch()
        actions.addWidget(close_button)
        actions.addWidget(self.apply_button)

        layout = QVBoxLayout(self)
        layout.addWidget(heading)
        layout.addWidget(self.summary)
        layout.addWidget(details)
        layout.addLayout(history_header)
        layout.addWidget(self.history_status)
        layout.addWidget(self.history, 1)
        layout.addLayout(actions)
        self.refresh(status)

    def _request_check(self) -> None:
        self.set_checking(True)
        self._check_now()

    def _request_history(self) -> None:
        self.set_history_loading(True)
        self._load_history()

    def _selected_build(self) -> AvailableBuild | None:
        row = self.history.currentRow()
        return self._builds[row] if 0 <= row < len(self._builds) else None

    def _selection_changed(self) -> None:
        selected = self._selected_build()
        self.download_button.setEnabled(
            self._status.supported
            and selected is not None
            and selected.revision != self._status.installed_revision
        )

    def _request_download(self) -> None:
        selected = self._selected_build()
        if selected is None:
            return
        if self._builds and selected.revision != self._builds[0].revision:
            answer = QMessageBox.warning(
                self,
                "Download Older Specter Build",
                "This is an older build. Data created by newer builds may not be "
                "compatible. Back up important investigations before installing it.\n\n"
                "Download this build?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.Cancel,
                QMessageBox.StandardButton.Cancel,
            )
            if answer != QMessageBox.StandardButton.Yes:
                return
        self.set_downloading(True)
        self._select_build(selected)

    def set_checking(self, checking: bool) -> None:
        self.check_button.setDisabled(checking)
        if checking:
            self.summary.setText("Checking GitHub for a newer Specter build...")

    def set_history_loading(self, loading: bool) -> None:
        self.history_button.setDisabled(loading)
        if loading:
            self.history_status.setText("Loading recent builds from GitHub...")

    def set_downloading(self, downloading: bool) -> None:
        self.download_button.setDisabled(downloading)
        if downloading:
            self.summary.setText("Downloading the selected build without installing it...")

    def set_history(self, builds: list[AvailableBuild], error: str = "") -> None:
        self.history_button.setEnabled(True)
        self._builds = builds
        self._render_history()
        if error:
            self.history_status.setText(error)
        elif builds:
            self.history_status.setText(
                "Choose any build to download. Installation happens only when you confirm it."
            )
        else:
            self.history_status.setText("No builds are available.")

    def _render_history(self) -> None:
        selected = self._selected_build()
        selected_revision = selected.revision if selected else None
        self.history.setRowCount(len(self._builds))
        for row, build in enumerate(self._builds):
            states = []
            if row == 0:
                states.append("Latest")
            if build.revision == self._status.installed_revision:
                states.append("Installed")
            if build.revision == self._status.pending_revision:
                states.append("Downloaded")
            values = (build.title, build.date_label, build.revision[:12], ", ".join(states))
            for column, value in enumerate(values):
                item = QTableWidgetItem(value)
                item.setToolTip(build.revision if column == 2 else value)
                if column == 0:
                    item.setData(Qt.ItemDataRole.UserRole, build.revision)
                self.history.setItem(row, column, item)
            if build.revision == selected_revision:
                self.history.selectRow(row)
        self._selection_changed()

    def refresh(self, status: UpdateStatus, message: str = "") -> None:
        self._status = status
        self.set_checking(False)
        self.installed.setText(status.installed_label)
        self.pending.setText(status.pending_label)
        self.check_button.setEnabled(status.supported)
        self.apply_button.setEnabled(status.pending_revision is not None)
        self._render_history()
        if message:
            self.summary.setText(message)
        elif not status.supported:
            self.summary.setText("Update management is available in installed Specter builds.")
        elif status.pending_selected:
            self.summary.setText("Your selected build is downloaded and ready to install.")
        elif status.pending_revision:
            self.summary.setText("A newer build is downloaded and ready to install.")
        else:
            self.summary.setText("No downloaded update is waiting.")


class SpecterWindow(QMainWindow):
    update_result = Signal(object)
    update_history_result = Signal(object)
    update_download_result = Signal(object)
    update_notice = Signal(str)

    def __init__(
        self,
        url: str,
        settings: DesktopSettings,
        *,
        update_checks_allowed: bool,
        instance_name: str,
    ):
        super().__init__()
        self._url = QUrl(url)
        self._settings = settings
        self._update_checks_allowed = update_checks_allowed
        self._update_monitor = None
        self._update_dialog: UpdateDialog | None = None
        self._checking_update = False
        self._loading_update_history = False
        self._downloading_build = False
        self._force_quit = False

        icon = QIcon(str(_icon_path()))
        self.setWindowIcon(icon)
        self.setWindowTitle("Specter")
        self.setMinimumSize(1024, 700)
        self.resize(settings.window_width, settings.window_height)

        self.view = QWebEngineView(self)
        page = SpecterPage(self._url, self.view)
        self.view.setPage(page)
        self.setCentralWidget(self.view)
        self.view.setZoomFactor(settings.zoom_percent / 100)
        self.view.titleChanged.connect(self._set_page_title)
        self.view.loadFinished.connect(self._page_loaded)

        self.bridge = DesktopBridge(self)
        self.bridge.notification.connect(self._notify)
        self.channel = QWebChannel(page)
        self.channel.registerObject("specterDesktop", self.bridge)
        page.setWebChannel(self.channel)

        self._build_menu()
        self._build_status_bar()
        self._build_tray(icon)
        self._build_instance_server(instance_name)

        self.update_result.connect(self._update_check_finished)
        self.update_history_result.connect(self._update_history_finished)
        self.update_download_result.connect(self._update_download_finished)
        self.update_notice.connect(self._background_update_ready)
        self._configure_update_monitor()
        self.view.load(self._url)
        if settings.maximized:
            self.showMaximized()

    def _standard_icon(self, theme: str, fallback: QStyle.StandardPixmap) -> QIcon:
        icon = QIcon.fromTheme(theme)
        return icon if not icon.isNull() else self.style().standardIcon(fallback)

    def _action(
        self,
        menu: QMenu,
        text: str,
        callback: Callable[[], None],
        *,
        shortcut: str | QKeySequence | None = None,
        icon: QIcon | None = None,
    ) -> QAction:
        action = QAction(icon or QIcon(), text, self)
        action.triggered.connect(callback)
        if shortcut:
            action.setShortcut(shortcut)
        menu.addAction(action)
        return action

    def _build_menu(self) -> None:
        file_menu = self.menuBar().addMenu("&File")
        self._action(
            file_menu,
            "New Investigation",
            self.new_investigation,
            shortcut=QKeySequence.StandardKey.New,
            icon=self._standard_icon("document-new", QStyle.StandardPixmap.SP_FileIcon),
        )
        file_menu.addSeparator()
        self._action(file_menu, "Exit Specter", self.quit_application, shortcut="Ctrl+Q")

        navigate = self.menuBar().addMenu("&Navigate")
        workspace = navigate.addMenu("Workspace")
        analysis = navigate.addMenu("Analysis")
        operations = navigate.addMenu("Operations")
        for label, tab in (
            ("New Investigation", "search"),
            ("Investigations", "investigations"),
            ("Evidence Review", "review"),
            ("Change Timeline", "timeline"),
        ):
            self._action(workspace, label, lambda checked=False, name=tab: self.open_tab(name))
        for label, tab in (
            ("Identity Graph", "graph"),
            ("Discovery Map", "map"),
            ("Insights", "insights"),
            ("Reasoning", "reasoning"),
            ("Confidence", "confidence"),
        ):
            self._action(analysis, label, lambda checked=False, name=tab: self.open_tab(name))
        for label, tab in (
            ("Source Health", "sources"),
            ("Modules and Keys", "keys"),
            ("Data Governance", "governance"),
            ("Administration", "administration"),
        ):
            self._action(operations, label, lambda checked=False, name=tab: self.open_tab(name))

        view_menu = self.menuBar().addMenu("&View")
        self._action(
            view_menu,
            "Back",
            self.view.back,
            shortcut=QKeySequence.StandardKey.Back,
            icon=self._standard_icon("go-previous", QStyle.StandardPixmap.SP_ArrowBack),
        )
        self._action(
            view_menu,
            "Forward",
            self.view.forward,
            shortcut=QKeySequence.StandardKey.Forward,
            icon=self._standard_icon("go-next", QStyle.StandardPixmap.SP_ArrowForward),
        )
        self._action(
            view_menu,
            "Reload",
            self.view.reload,
            shortcut=QKeySequence.StandardKey.Refresh,
            icon=self._standard_icon("view-refresh", QStyle.StandardPixmap.SP_BrowserReload),
        )
        view_menu.addSeparator()
        self._action(view_menu, "Zoom In", lambda: self._change_zoom(10), shortcut="Ctrl++")
        self._action(view_menu, "Zoom Out", lambda: self._change_zoom(-10), shortcut="Ctrl+-")
        self._action(view_menu, "Actual Size", lambda: self._set_zoom(100), shortcut="Ctrl+0")
        self._action(view_menu, "Full Screen", self._toggle_fullscreen, shortcut="F11")

        tools_menu = self.menuBar().addMenu("&Tools")
        self._action(tools_menu, "Settings", self.show_settings, shortcut="Ctrl+,")
        self._action(tools_menu, "Update Manager", self.show_updates)
        tools_menu.addSeparator()
        self._action(tools_menu, "Open Data Folder", lambda: self._open_folder(data_root()))
        self._action(
            tools_menu,
            "Open Log Folder",
            lambda: self._open_folder(state_root() / "logs"),
        )

        help_menu = self.menuBar().addMenu("&Help")
        self._action(
            help_menu,
            "Documentation",
            lambda: QDesktopServices.openUrl(
                QUrl("https://github.com/gahitchi/osint-recon/tree/gpt-branch#readme")
            ),
        )
        self._action(
            help_menu,
            "Report an Issue",
            lambda: QDesktopServices.openUrl(
                QUrl("https://github.com/gahitchi/osint-recon/issues/new")
            ),
        )
        help_menu.addSeparator()
        self._action(help_menu, "About Specter", self.show_about)

    def _build_status_bar(self) -> None:
        self.statusBar().showMessage("Connecting to the local Specter service...")
        self.build_label = QLabel(f"Specter {__version__}")
        self.statusBar().addPermanentWidget(self.build_label)

    def _build_tray(self, icon: QIcon) -> None:
        self.tray: QSystemTrayIcon | None = None
        if not QSystemTrayIcon.isSystemTrayAvailable():
            return
        self.tray = QSystemTrayIcon(icon, self)
        self.tray.setToolTip("Specter")
        menu = QMenu(self)
        self._action(menu, "Show Specter", self.show_and_raise)
        self._action(menu, "New Investigation", self.new_investigation)
        self._action(menu, "Check for Updates", self.check_updates)
        menu.addSeparator()
        self._action(menu, "Exit Specter", self.quit_application)
        self.tray.setContextMenu(menu)
        self.tray.activated.connect(self._tray_activated)
        self.tray.show()

    def _build_instance_server(self, name: str) -> None:
        self.instance_server = QLocalServer(self)
        self.instance_server.newConnection.connect(self._instance_message)
        self.instance_primary = self.instance_server.listen(name)
        if self.instance_primary:
            return
        # Another process may have won the launch race after our initial probe.
        if _activate_existing(name):
            return
        QLocalServer.removeServer(name)
        self.instance_primary = self.instance_server.listen(name)
        if not self.instance_primary:
            raise RuntimeError("Specter could not create its local application channel")

    def _instance_message(self) -> None:
        while self.instance_server.hasPendingConnections():
            connection = self.instance_server.nextPendingConnection()
            if connection is not None:
                connection.waitForReadyRead(100)
                connection.deleteLater()
        self.show_and_raise()

    def _set_page_title(self, title: str) -> None:
        clean = title.removesuffix(" - Specter").strip()
        self.setWindowTitle("Specter" if not clean else f"{clean} - Specter")

    def _page_loaded(self, success: bool) -> None:
        if success:
            self.statusBar().showMessage("Local service connected", 5000)
            self.view.page().runJavaScript(_BRIDGE_SCRIPT)
        else:
            self.statusBar().showMessage("The local workspace could not be loaded")
            self._notify(
                "Specter could not connect",
                "The local service did not respond. Reload the workspace or restart Specter.",
                "error",
            )

    def _tray_activated(self, reason: QSystemTrayIcon.ActivationReason) -> None:
        if reason in {
            QSystemTrayIcon.ActivationReason.Trigger,
            QSystemTrayIcon.ActivationReason.DoubleClick,
        }:
            self.show_and_raise()

    def show_and_raise(self) -> None:
        self.showNormal() if self.isMinimized() else self.show()
        self.raise_()
        self.activateWindow()

    def open_tab(self, tab: str) -> None:
        script = (
            "document.querySelector("
            + json.dumps(f'#tabs button[data-tab="{tab}"]')
            + ")?.click();"
        )
        self.view.page().runJavaScript(script)
        self.show_and_raise()

    def new_investigation(self) -> None:
        self.open_tab("search")
        QTimer.singleShot(
            80,
            lambda: self.view.page().runJavaScript(
                'document.querySelector("#q input[name=name]")?.focus();'
            ),
        )

    def _change_zoom(self, amount: int) -> None:
        self._set_zoom(round(self.view.zoomFactor() * 100) + amount)

    def _set_zoom(self, percent: int) -> None:
        percent = max(75, min(175, percent))
        self.view.setZoomFactor(percent / 100)
        self._settings = DesktopSettings(**{**self._settings.__dict__, "zoom_percent": percent})
        self.statusBar().showMessage(f"Zoom: {percent}%", 2500)

    def _toggle_fullscreen(self) -> None:
        self.showNormal() if self.isFullScreen() else self.showFullScreen()

    def _open_folder(self, path: Path) -> None:
        path.mkdir(parents=True, exist_ok=True)
        QDesktopServices.openUrl(QUrl.fromLocalFile(str(path.resolve())))

    def show_settings(self) -> None:
        dialog = SettingsDialog(self._settings, self)
        dialog.settings_saved.connect(self._save_settings)
        dialog.exec()

    def _save_settings(self, settings: DesktopSettings) -> None:
        self._settings = settings
        self.view.setZoomFactor(settings.zoom_percent / 100)
        save_desktop_settings(settings)
        self._configure_update_monitor()
        self.statusBar().showMessage("Settings saved", 3000)

    def _settings_with_geometry(self) -> DesktopSettings:
        size = self.normalGeometry().size() if self.isMaximized() else self.size()
        return DesktopSettings(
            **{
                **self._settings.__dict__,
                "window_width": size.width(),
                "window_height": size.height(),
                "maximized": self.isMaximized(),
                "zoom_percent": round(self.view.zoomFactor() * 100),
            }
        )

    def _configure_update_monitor(self) -> None:
        if self._update_monitor is not None:
            self._update_monitor.stop()
            self._update_monitor = None
        if self._update_checks_allowed and self._settings.check_for_updates:
            self._update_monitor = start_update_monitor(notify=self.update_notice.emit)

    def show_updates(self) -> None:
        status = get_update_status()
        if self._update_dialog is None:
            self._update_dialog = UpdateDialog(
                status,
                self.check_updates,
                self.load_update_history,
                self.download_update_build,
                self.request_apply_update,
                self,
            )
            self._update_dialog.finished.connect(lambda _result: self._clear_update_dialog())
            QTimer.singleShot(0, self.load_update_history)
        else:
            self._update_dialog.refresh(status)
        self._update_dialog.show()
        self._update_dialog.raise_()
        self._update_dialog.activateWindow()

    def _clear_update_dialog(self) -> None:
        self._update_dialog = None

    def check_updates(self) -> None:
        if self._checking_update:
            return
        self._checking_update = True
        self.statusBar().showMessage("Checking for updates...")
        if self._update_dialog is not None:
            self._update_dialog.set_checking(True)

        def run() -> None:
            self.update_result.emit(check_for_update(force=True))

        threading.Thread(target=run, name="specter-manual-update-check", daemon=True).start()

    def load_update_history(self) -> None:
        if self._loading_update_history:
            return
        self._loading_update_history = True
        if self._update_dialog is not None:
            self._update_dialog.set_history_loading(True)

        def run() -> None:
            try:
                result = (list_available_builds(), "")
            except (OSError, ValueError, json.JSONDecodeError):
                result = ([], "Version history is temporarily unavailable. Try again later.")
            self.update_history_result.emit(result)

        threading.Thread(target=run, name="specter-version-history", daemon=True).start()

    def _update_history_finished(self, result: tuple[list[AvailableBuild], str]) -> None:
        self._loading_update_history = False
        builds, error = result
        if self._update_dialog is not None:
            self._update_dialog.set_history(builds, error)

    def download_update_build(self, build: AvailableBuild) -> None:
        if self._downloading_build:
            return
        self._downloading_build = True
        if self._update_dialog is not None:
            self._update_dialog.set_downloading(True)

        def run() -> None:
            self.update_download_result.emit(download_build(build.revision, title=build.title))

        threading.Thread(target=run, name="specter-build-download", daemon=True).start()

    def _update_download_finished(self, result: UpdateResult) -> None:
        self._downloading_build = False
        message = result.message or "The selected build could not be downloaded."
        self.statusBar().showMessage(message, 8000)
        if self._update_dialog is not None:
            self._update_dialog.refresh(get_update_status(), message)
        if result.downloaded:
            self._notify("Specter build ready", message, "info")

    def _update_check_finished(self, result: UpdateResult) -> None:
        self._checking_update = False
        message = result.message or "Updates are unavailable for this installation."
        self.statusBar().showMessage(message, 8000)
        status = get_update_status()
        if self._update_dialog is not None:
            self._update_dialog.refresh(status, message)
        if result.update_available:
            self._notify("Specter update ready", message, "info")

    def _background_update_ready(self, message: str) -> None:
        self.statusBar().showMessage(message, 10000)
        if self._update_dialog is not None:
            self._update_dialog.refresh(get_update_status(), message)
        self._notify("Specter update ready", message, "info")

    def request_apply_update(self) -> None:
        if get_update_status().pending_revision is None:
            self.check_updates()
            return
        answer = QMessageBox.question(
            self,
            "Install Specter Update",
            "Specter will close, install the downloaded update, and restart. Continue?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.Cancel,
            QMessageBox.StandardButton.Yes,
        )
        if answer != QMessageBox.StandardButton.Yes:
            return
        self._force_quit = True
        save_desktop_settings(self._settings_with_geometry())
        QApplication.exit(APPLY_UPDATE_EXIT_CODE)

    def _notify(self, title: str, message: str, level: str = "info") -> None:
        if not self._settings.notifications or not message:
            return
        if self.tray is None or not QSystemTrayIcon.supportsMessages():
            return
        icon = {
            "error": QSystemTrayIcon.MessageIcon.Critical,
            "warning": QSystemTrayIcon.MessageIcon.Warning,
        }.get(level, QSystemTrayIcon.MessageIcon.Information)
        self.tray.showMessage(title, message, icon, 7000)

    def show_about(self) -> None:
        QMessageBox.about(
            self,
            "About Specter",
            f"<h3>Specter {__version__}</h3>"
            "<p>Local-first research and evidence analysis.</p>"
            "<p>Copyright (c) gahitchi. Released under the MIT License.</p>",
        )

    def quit_application(self) -> None:
        self._force_quit = True
        self.close()

    def closeEvent(self, event: QCloseEvent) -> None:
        self._settings = self._settings_with_geometry()
        save_desktop_settings(self._settings)
        if not self._force_quit and self._settings.close_to_tray and self.tray is not None:
            event.ignore()
            self.hide()
            self._notify("Specter is still running", "Use the tray icon to reopen or exit.")
            return
        if self._update_monitor is not None:
            self._update_monitor.stop()
            self._update_monitor = None
        event.accept()

    def shutdown(self) -> None:
        if self._update_monitor is not None:
            self._update_monitor.stop()
            self._update_monitor = None
        if self.tray is not None:
            self.tray.hide()


def _activate_existing(name: str) -> bool:
    connection = QLocalSocket()
    connection.connectToServer(name)
    if not connection.waitForConnected(300):
        return False
    connection.write(b"show")
    connection.waitForBytesWritten(300)
    connection.disconnectFromServer()
    return True


def run_desktop(
    url: str,
    *,
    update_checks_allowed: bool = True,
    instance_key: str = "default",
) -> str:
    """Run the native desktop event loop and return the requested exit action."""
    QApplication.setApplicationName("Specter")
    QApplication.setOrganizationName("Specter")
    QApplication.setDesktopFileName("specter")
    app = QApplication.instance() or QApplication([])
    app.setQuitOnLastWindowClosed(True)
    app.setWindowIcon(QIcon(str(_icon_path())))
    app.setStyleSheet(_APP_STYLESHEET)

    name = _instance_name(instance_key)
    if _activate_existing(name):
        return "activated"

    settings = load_desktop_settings()
    window = SpecterWindow(
        url,
        settings,
        update_checks_allowed=update_checks_allowed,
        instance_name=name,
    )
    if not window.instance_primary:
        window.shutdown()
        window.deleteLater()
        return "activated"
    window.show()
    startup_notice = os.environ.pop("SPECTER_STARTUP_NOTICE", "").strip()
    if startup_notice:
        QTimer.singleShot(
            500,
            lambda: (
                window.statusBar().showMessage(startup_notice, 10000),
                window._notify("Specter update", startup_notice),
            ),
        )
    result = app.exec()
    window.shutdown()
    return "apply-update" if result == APPLY_UPDATE_EXIT_CODE else "quit"
