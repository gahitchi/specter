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
rm -f "$data_directory/icons/hicolor/scalable/apps/specter.svg"
printf 'Specter was removed. Investigation data and settings were left in place.\n'
