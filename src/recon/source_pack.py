"""Validate and install a broad WhatsMyName username source pack."""

from __future__ import annotations

import hashlib
import ipaddress
import json
from pathlib import Path
from urllib.parse import urlsplit

from .config import Settings
from .models import SiteRule

OFFICIAL_URL = "https://raw.githubusercontent.com/WebBreacher/WhatsMyName/main/wmn-data.json"
LICENSE = "CC BY 4.0"
MAX_BYTES = 10_000_000
_DEFAULT = Path(__file__).resolve().parent / "data" / "sites.json"


def uses_external_pack(settings: Settings) -> bool:
    return Path(settings.sites_data_file).expanduser().resolve() != _DEFAULT.resolve()


def _convert(entry: dict) -> dict:
    from .collectors.username import _from_wmn, _is_wmn

    return _from_wmn(entry) if _is_wmn(entry) else entry


def validate(payload: bytes) -> tuple[dict, dict]:
    if len(payload) > MAX_BYTES:
        raise ValueError("source pack exceeds 10 MB")
    raw = json.loads(payload)
    if not isinstance(raw, dict) or not isinstance(raw.get("sites"), list):
        raise ValueError("source pack must contain a 'sites' list")
    accepted = []
    rejected = []
    seen = set()
    for index, entry in enumerate(raw["sites"]):
        try:
            if not isinstance(entry, dict):
                raise ValueError("entry is not an object")
            converted = _convert(entry)
            rule = SiteRule.model_validate(converted)
            if rule.uri_check.count("{account}") != 1:
                raise ValueError("URL must contain exactly one {account} placeholder")
            parts = urlsplit(rule.uri_check.replace("{account}", "recon-canary"))
            if parts.scheme != "https" or not parts.hostname or parts.username or parts.password:
                raise ValueError("only credential-free HTTPS source URLs are accepted")
            host = parts.hostname.rstrip(".").casefold()
            if host == "localhost" or host.endswith((".localhost", ".local")):
                raise ValueError("local network source hosts are rejected")
            try:
                address = ipaddress.ip_address(host)
            except ValueError:
                address = None
            if address is not None and not address.is_global:
                raise ValueError("non-public IP source hosts are rejected")
            if rule.uri_pretty:
                pretty = urlsplit(rule.uri_pretty.replace("{account}", "recon-canary"))
                if pretty.scheme != "https" or not pretty.hostname:
                    raise ValueError("pretty URLs must also use HTTPS")
            key = (rule.name.casefold(), rule.uri_check)
            if key in seen:
                raise ValueError("duplicate source")
            seen.add(key)
            accepted.append(entry)
        except Exception as exc:  # noqa: BLE001 - report every invalid upstream row
            rejected.append({"index": index, "reason": str(exc)[:200]})
    if len(accepted) < 25:
        raise ValueError(f"source pack has too few valid HTTPS sources ({len(accepted)})")
    sanitized = {**raw, "sites": accepted}
    manifest = {
        "schema": 1,
        "source": OFFICIAL_URL,
        "license": LICENSE,
        "sha256_input": hashlib.sha256(payload).hexdigest(),
        "accepted": len(accepted),
        "rejected": len(rejected),
        "rejections": rejected,
    }
    return sanitized, manifest


def install(input_file: str | Path, output_file: str | Path) -> dict:
    source = Path(input_file).expanduser()
    sanitized, manifest = validate(source.read_bytes())
    destination = Path(output_file).expanduser()
    destination.parent.mkdir(parents=True, exist_ok=True)
    encoded = json.dumps(sanitized, indent=2, ensure_ascii=True).encode("utf-8")
    destination.write_bytes(encoded)
    manifest["sha256_installed"] = hashlib.sha256(encoded).hexdigest()
    manifest_path = destination.with_suffix(destination.suffix + ".manifest.json")
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return {**manifest, "path": str(destination), "manifest": str(manifest_path)}
