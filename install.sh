#!/usr/bin/env bash
set -euo pipefail

PACKAGE_SPEC='osint-recon @ git+https://github.com/gahitchi/osint-recon.git@gpt-branch'

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
printf 'Specter installed successfully. While running, it checks for updates every 5 minutes.\n'
printf 'Launch at any time with: specter\n'
printf 'Apply a downloaded update with: specter --update\n'
printf 'Uninstall with: uv tool uninstall osint-recon\n'

case ":$PATH:" in
  *":$bin_directory:"*) ;;
  *) export PATH="$bin_directory:$PATH" ;;
esac

if [[ "${1:-}" != "--no-launch" ]]; then
  "$bin_directory/specter" --no-update
fi
