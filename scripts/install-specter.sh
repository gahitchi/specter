#!/usr/bin/env bash
# Development helper for exposing Specter commands from this checkout.
#
# Usage:  ./scripts/install-specter.sh
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
VENV="$REPO/.venv"
BIN="${XDG_BIN_HOME:-$HOME/.local/bin}"

if [ ! -x "$VENV/bin/specter" ]; then
  echo "Setting up virtualenv at $VENV ..."
  python -m venv "$VENV"
  "$VENV/bin/pip" install -q -e "$REPO[desktop]"
fi

mkdir -p "$BIN"
ln -sf "$VENV/bin/specter" "$BIN/specter"
ln -sf "$VENV/bin/specter-app" "$BIN/specter-app"

echo "Installed: $BIN/specter"
case ":$PATH:" in
  *":$BIN:"*) echo "Ready — type 'specter' in a new terminal." ;;
  *) echo "NOTE: add $BIN to your PATH, e.g.  export PATH=\"$BIN:\$PATH\"" ;;
esac
