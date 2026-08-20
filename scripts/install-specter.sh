#!/usr/bin/env bash
# Install the `specter` terminal command: wakes the whole Specter stack
# (server + worker + scheduler) and opens the dashboard in a Firefox tab.
#
# Usage:  ./scripts/install-specter.sh
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
VENV="$REPO/.venv"
BIN="${XDG_BIN_HOME:-$HOME/.local/bin}"

if [ ! -x "$VENV/bin/specter" ]; then
  echo "Setting up virtualenv at $VENV ..."
  python -m venv "$VENV"
  "$VENV/bin/pip" install -q -e "$REPO"
fi

mkdir -p "$BIN"
cat > "$BIN/specter" <<EOF
#!/usr/bin/env bash
# Specter launcher - wakes the stack and opens the dashboard in Firefox.
exec "$VENV/bin/specter" "\$@"
EOF
chmod +x "$BIN/specter"

echo "Installed: $BIN/specter"
case ":$PATH:" in
  *":$BIN:"*) echo "Ready — type 'specter' in a new terminal." ;;
  *) echo "NOTE: add $BIN to your PATH, e.g.  export PATH=\"$BIN:\$PATH\"" ;;
esac
