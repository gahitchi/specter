"""Persistent preferences for the Specter desktop application."""

from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass
from pathlib import Path


def config_root() -> Path:
    override = os.environ.get("SPECTER_CONFIG_DIR")
    if override:
        return Path(override).expanduser()
    if os.name == "nt" and os.environ.get("APPDATA"):
        return Path(os.environ["APPDATA"]) / "Specter"
    return Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config")) / "specter"


def data_root() -> Path:
    override = os.environ.get("SPECTER_DATA_DIR")
    if override:
        return Path(override).expanduser()
    if os.name == "nt" and os.environ.get("LOCALAPPDATA"):
        return Path(os.environ["LOCALAPPDATA"]) / "Specter"
    return Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share")) / "specter"


def state_root() -> Path:
    override = os.environ.get("SPECTER_STATE_DIR")
    if override:
        return Path(override).expanduser()
    if os.name == "nt" and os.environ.get("LOCALAPPDATA"):
        return Path(os.environ["LOCALAPPDATA"]) / "Specter"
    return Path(os.environ.get("XDG_STATE_HOME", Path.home() / ".local" / "state")) / "specter"


@dataclass(frozen=True)
class DesktopSettings:
    check_for_updates: bool = True
    notifications: bool = True
    close_to_tray: bool = False
    background_services: bool = True
    maigret_enabled: bool = False
    zoom_percent: int = 100
    window_width: int = 1440
    window_height: int = 900
    maximized: bool = False

    @classmethod
    def from_mapping(cls, payload: object) -> DesktopSettings:
        if not isinstance(payload, dict):
            return cls()
        defaults = cls()

        def boolean(name: str) -> bool:
            value = payload.get(name)
            return value if isinstance(value, bool) else getattr(defaults, name)

        def integer(name: str, minimum: int, maximum: int) -> int:
            value = payload.get(name)
            if isinstance(value, bool) or not isinstance(value, int):
                return getattr(defaults, name)
            return max(minimum, min(maximum, value))

        return cls(
            check_for_updates=boolean("check_for_updates"),
            notifications=boolean("notifications"),
            close_to_tray=boolean("close_to_tray"),
            background_services=boolean("background_services"),
            maigret_enabled=boolean("maigret_enabled"),
            zoom_percent=integer("zoom_percent", 75, 175),
            window_width=integer("window_width", 1024, 3840),
            window_height=integer("window_height", 700, 2160),
            maximized=boolean("maximized"),
        )


def load_desktop_settings(path: Path | None = None) -> DesktopSettings:
    settings_path = path or config_root() / "settings.json"
    try:
        payload = json.loads(settings_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return DesktopSettings()
    return DesktopSettings.from_mapping(payload)


def save_desktop_settings(settings: DesktopSettings, path: Path | None = None) -> Path:
    settings_path = path or config_root() / "settings.json"
    settings_path.parent.mkdir(parents=True, exist_ok=True)
    temporary = settings_path.with_suffix(settings_path.suffix + ".tmp")
    temporary.write_text(json.dumps(asdict(settings), indent=2) + "\n", encoding="utf-8")
    try:
        temporary.chmod(0o600)
    except OSError:
        pass
    os.replace(temporary, settings_path)
    return settings_path
