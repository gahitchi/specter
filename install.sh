#!/usr/bin/env bash
set -euo pipefail

PACKAGE_SPEC='osint-recon[desktop] @ git+https://github.com/gahitchi/osint-recon.git@gpt-branch'

if ! command -v curl >/dev/null 2>&1; then
  printf 'curl is required. Install it with: sudo pacman -S curl\n' >&2
  exit 1
fi

if ! command -v uv >/dev/null 2>&1; then
  printf 'Installing the uv package manager...\n'
  curl -LsSf https://astral.sh/uv/install.sh | sh
  export PATH="$HOME/.local/bin:$HOME/.cargo/bin:$PATH"
fi

if ! command -v uv >/dev/null 2>&1; then
  printf 'uv was installed but is not available in PATH. Open a new shell and retry.\n' >&2
  exit 1
fi

printf 'Installing Specter in an isolated user environment...\n'
uv tool install --force --refresh-package osint-recon "$PACKAGE_SPEC"

bin_directory="$(uv tool dir --bin)"
data_directory="${XDG_DATA_HOME:-$HOME/.local/share}"
applications_directory="$data_directory/applications"
icon_directory="$data_directory/icons/hicolor/512x512/apps"
mkdir -p "$applications_directory" "$icon_directory"
icon_source="$("$bin_directory/specter" --icon-path)"
if [[ ! -f "$icon_source" ]]; then
  printf 'Specter was installed but its application icon is missing.\n' >&2
  exit 1
fi
install -m 0644 "$icon_source" "$icon_directory/specter.png"
printf '%s\n' \
  '[Desktop Entry]' \
  'Type=Application' \
  'Name=Specter' \
  'Comment=Research and evidence workspace' \
  "Exec=\"$bin_directory/specter-app\"" \
  'Icon=specter' \
  'Terminal=false' \
  'Categories=Utility;Security;' \
  'StartupNotify=true' \
  > "$applications_directory/specter.desktop"
chmod 0644 "$applications_directory/specter.desktop"

desktop_directory=""
if command -v xdg-user-dir >/dev/null 2>&1; then
  desktop_directory="$(xdg-user-dir DESKTOP 2>/dev/null || true)"
fi
if [[ -z "$desktop_directory" || "$desktop_directory" == "$HOME" ]]; then
  desktop_directory="$HOME/Desktop"
fi
mkdir -p "$desktop_directory"
install -m 0755 "$applications_directory/specter.desktop" "$desktop_directory/Specter.desktop"
if command -v gio >/dev/null 2>&1; then
  gio set "$desktop_directory/Specter.desktop" metadata::trusted true >/dev/null 2>&1 || true
fi
if command -v update-desktop-database >/dev/null 2>&1; then
  update-desktop-database "$applications_directory" >/dev/null 2>&1 || true
fi

printf 'Specter installed successfully. While running, it checks for updates every 5 minutes.\n'
printf 'Open Specter from the desktop, application menu, or launch it with: specter\n'
printf 'Apply a downloaded update with: specter --update\n'
printf 'Uninstall with: curl -LsSf https://raw.githubusercontent.com/gahitchi/osint-recon/gpt-branch/uninstall.sh | bash\n'

case ":$PATH:" in
  *":$bin_directory:"*) ;;
  *) export PATH="$bin_directory:$PATH" ;;
esac

if [[ "${1:-}" != "--no-launch" ]]; then
  nohup "$bin_directory/specter-app" --no-update >/dev/null 2>&1 &
fi
