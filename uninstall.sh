#!/usr/bin/env bash
set -euo pipefail

if ! command -v uv >/dev/null 2>&1; then
  export PATH="$HOME/.local/bin:$HOME/.cargo/bin:$PATH"
fi
if ! command -v uv >/dev/null 2>&1; then
  printf 'uv could not be found. Install uv or remove the osint-recon tool environment manually.\n' >&2
  exit 1
fi

uv tool uninstall osint-recon
data_directory="${XDG_DATA_HOME:-$HOME/.local/share}"
rm -f "$data_directory/applications/specter.desktop"
rm -f "$data_directory/icons/hicolor/512x512/apps/specter.png"
rm -f "$data_directory/icons/hicolor/scalable/apps/specter.svg"
desktop_directory=""
if command -v xdg-user-dir >/dev/null 2>&1; then
  desktop_directory="$(xdg-user-dir DESKTOP 2>/dev/null || true)"
fi
if [[ -z "$desktop_directory" || "$desktop_directory" == "$HOME" ]]; then
  desktop_directory="$HOME/Desktop"
fi
rm -f "$desktop_directory/Specter.desktop"
if [[ "$desktop_directory" != "$HOME/Desktop" ]]; then
  rm -f "$HOME/Desktop/Specter.desktop"
fi
if command -v update-desktop-database >/dev/null 2>&1; then
  update-desktop-database "$data_directory/applications" >/dev/null 2>&1 || true
fi
printf 'Specter and its launchers were removed. Investigation data and settings were left in place.\n'
