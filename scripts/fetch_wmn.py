#!/usr/bin/env python3
"""Download the official WhatsMyName dataset (600+ sites) for broad username
coverage. The curated dataset bundled with Specter stays the zero-setup default;
this is opt-in.

Usage:
    python scripts/fetch_wmn.py            # -> data/wmn-data.json
    RECON_SITES_FILE=data/wmn-data.json specter scan --username torvalds

The loader (`recon.collectors.username.load_sites`) understands the raw wmn
schema natively (via `_from_wmn`), so no conversion step is needed.
"""

from __future__ import annotations

import sys
import urllib.request
from pathlib import Path

from recon.source_pack import install

WMN_URL = "https://raw.githubusercontent.com/WebBreacher/WhatsMyName/main/wmn-data.json"
DEST = Path(__file__).resolve().parents[1] / "data" / "wmn-data.json"


def main() -> int:
    print(f"fetching {WMN_URL} ...", file=sys.stderr)
    try:
        # WMN_URL is a fixed HTTPS URL controlled by this script.
        with urllib.request.urlopen(WMN_URL, timeout=30) as resp:  # nosec B310
            raw = resp.read(10_000_001)
    except Exception as e:  # noqa: BLE001
        print(f"error: download failed: {e}", file=sys.stderr)
        return 1

    DEST.parent.mkdir(parents=True, exist_ok=True)
    raw_path = DEST.with_suffix(".download.json")
    raw_path.write_bytes(raw)
    try:
        result = install(raw_path, DEST)
    except ValueError as e:
        print(f"error: invalid dataset: {e}", file=sys.stderr)
        return 1
    finally:
        raw_path.unlink(missing_ok=True)
    print(f"wrote {result['accepted']} HTTPS sites to {DEST} "
          f"({result['rejected']} rejected)")
    print(f"enable after maturity passes: RECON_ENABLE_EXPANSION=1 "
          f"RECON_SITES_FILE={DEST.relative_to(DEST.parents[1])} "
          "specter scan --username <handle>")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
