from __future__ import annotations

import json

from recon.desktop_settings import (
    DesktopSettings,
    config_root,
    data_root,
    load_desktop_settings,
    save_desktop_settings,
    state_root,
)


def test_desktop_settings_round_trip(tmp_path):
    path = tmp_path / "settings.json"
    expected = DesktopSettings(
        check_for_updates=False,
        notifications=False,
        close_to_tray=True,
        background_services=False,
        maigret_enabled=True,
        zoom_percent=125,
        window_width=1280,
        window_height=800,
        maximized=True,
    )

    assert save_desktop_settings(expected, path) == path
    assert load_desktop_settings(path) == expected
    assert json.loads(path.read_text(encoding="utf-8"))["zoom_percent"] == 125


def test_desktop_settings_reject_invalid_types_and_bound_numbers(tmp_path):
    path = tmp_path / "settings.json"
    path.write_text(json.dumps({
        "check_for_updates": "yes",
        "notifications": 1,
        "close_to_tray": True,
        "zoom_percent": 900,
        "window_width": 12,
        "window_height": 99999,
    }), encoding="utf-8")

    settings = load_desktop_settings(path)

    assert settings.check_for_updates is True
    assert settings.notifications is True
    assert settings.close_to_tray is True
    assert settings.maigret_enabled is False
    assert settings.zoom_percent == 175
    assert settings.window_width == 1024
    assert settings.window_height == 2160


def test_desktop_paths_support_explicit_overrides(monkeypatch, tmp_path):
    config = tmp_path / "config"
    data = tmp_path / "data"
    state = tmp_path / "state"
    monkeypatch.setenv("SPECTER_CONFIG_DIR", str(config))
    monkeypatch.setenv("SPECTER_DATA_DIR", str(data))
    monkeypatch.setenv("SPECTER_STATE_DIR", str(state))

    assert config_root() == config
    assert data_root() == data
    assert state_root() == state


def test_malformed_settings_fall_back_to_defaults(tmp_path):
    path = tmp_path / "settings.json"
    path.write_text("not json", encoding="utf-8")

    assert load_desktop_settings(path) == DesktopSettings()
