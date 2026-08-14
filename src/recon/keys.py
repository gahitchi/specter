"""Optional API-key vault.

osint-recon is keyless-first: every default module runs with no credentials. The
engine is built so *keyed* modules (Shodan, VirusTotal, AbuseIPDB, ...) plug in
without re-architecting — a module declares `requires_keys`, and the engine skips
it when the named keys are absent.

Keys are read from (in priority order):
  1. environment variables, upper-cased + prefixed, e.g. RECON_KEY_SHODAN
  2. the operating-system keyring when RECON_KEY_BACKEND=keyring
  3. <config>/keys.toml   ([keys] shodan = "...")   (the default)

The web UI can also *write* keys (local-first, 127.0.0.1 only); the file is
created 0600 and values are never returned by the API.
"""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

from .config import env_value

try:
    import tomllib
except ModuleNotFoundError:  # Python 3.10
    import tomli as tomllib

# Catalogue of keys osint-recon knows how to use. `optional` keys merely enhance a
# keyless module (higher rate limit / richer data); non-optional keys gate a module
# that does nothing without them.
KNOWN_KEYS: list[dict] = [
    {"name": "shodan", "optional": False,
     "description": "Shodan host data (IP → open ports/services/hostnames)"},
    {"name": "virustotal", "optional": False,
     "description": "VirusTotal reputation for domains/IPs"},
    {"name": "abuseipdb", "optional": False,
     "description": "AbuseIPDB abuse-confidence score for IPs"},
    {"name": "github", "optional": True,
     "description": "GitHub token — raises the public API rate limit (60→5000/hr)"},
    {"name": "hibp", "optional": True,
     "description": "HaveIBeenPwned — richer breach data alongside keyless XposedOrNot"},
]

_DEFAULT_PATH = Path.home() / ".config" / "osint-recon" / "keys.toml"
_KEYRING_SERVICE = "osint-recon"


def _dump_toml(keys: dict[str, str]) -> str:
    lines = ["[keys]"]
    for k in sorted(keys):
        v = str(keys[k]).replace("\\", "\\\\").replace('"', '\\"')
        lines.append(f'{k} = "{v}"')
    return "\n".join(lines) + "\n"


class KeyVault:
    def __init__(self, path: Path | None = None) -> None:
        # When path is None the location is resolved from RECON_KEYS_FILE at access
        # time, so tests (and runtime env changes) take effect without a restart.
        self._explicit_path = path
        self._file_keys: dict[str, str] = {}
        self._loaded = False

    @property
    def path(self) -> Path:
        if self._explicit_path is not None:
            return self._explicit_path
        return Path(os.environ.get("RECON_KEYS_FILE") or _DEFAULT_PATH)

    @property
    def backend(self) -> str:
        backend = os.environ.get("RECON_KEY_BACKEND", "file").lower()
        if backend not in {"file", "keyring"}:
            raise ValueError("RECON_KEY_BACKEND must be 'file' or 'keyring'")
        return backend

    @staticmethod
    def _keyring_get(name: str) -> str | None:
        try:
            import keyring

            return keyring.get_password(_KEYRING_SERVICE, name.lower())
        except Exception:  # noqa: BLE001 - an unavailable backend must not break scans
            return None

    @staticmethod
    def _keyring_write(name: str, value: str | None) -> None:
        try:
            import keyring

            if value is None:
                try:
                    keyring.delete_password(_KEYRING_SERVICE, name.lower())
                except keyring.errors.PasswordDeleteError:
                    pass
            else:
                keyring.set_password(_KEYRING_SERVICE, name.lower(), value)
        except ImportError as exc:
            raise RuntimeError(
                "OS keyring storage requires the 'secure' optional dependency"
            ) from exc
        except Exception as exc:
            raise RuntimeError(f"OS keyring operation failed: {exc}") from exc

    def reload(self) -> None:
        """Force a re-read on next access (used after writes / in tests)."""
        self._loaded = False
        self._file_keys = {}

    def _load(self) -> None:
        if self._loaded:
            return
        self._loaded = True
        try:
            p = self.path
            if p.is_file():
                data = tomllib.loads(p.read_text(encoding="utf-8"))
                keys = data.get("keys", data)
                self._file_keys = {str(k).lower(): str(v) for k, v in keys.items()}
        except Exception:  # noqa: BLE001 - a malformed key file must not crash a scan
            self._file_keys = {}

    # --- read ---------------------------------------------------------------

    def get(self, name: str) -> str | None:
        env = env_value(f"RECON_KEY_{name.upper()}")
        if env:
            return env
        if self.backend == "keyring":
            return self._keyring_get(name)
        self._load()
        return self._file_keys.get(name.lower())

    def has(self, name: str) -> bool:
        return bool(self.get(name))

    def has_all(self, names: list[str]) -> bool:
        return all(self.has(n) for n in names)

    def source(self, name: str) -> str | None:
        """Where a key is configured: 'env', 'file', or None. Never the value."""
        env_name = f"RECON_KEY_{name.upper()}"
        if os.environ.get(env_name):
            return "env"
        if os.environ.get(f"{env_name}_FILE"):
            return "secret-file" if env_value(env_name) else None
        if self.backend == "keyring":
            return "keyring" if self._keyring_get(name) else None
        self._load()
        return "file" if self._file_keys.get(name.lower()) else None

    def status(self) -> list[dict]:
        """Catalogue + configured/source flags for the UI. Values are never exposed."""
        return [
            {**k, "configured": self.has(k["name"]), "source": self.source(k["name"])}
            for k in KNOWN_KEYS
        ]

    # --- write (local-first; file is 0600) ----------------------------------

    def set(self, name: str, value: str) -> None:
        if name.lower() not in {key["name"] for key in KNOWN_KEYS}:
            raise ValueError(f"unknown key: {name}")
        if not value:
            raise ValueError("key value cannot be empty; use clear() instead")
        if self.backend == "keyring":
            self._keyring_write(name, value)
            self.reload()
            return
        self._load()
        self._file_keys[name.lower()] = value
        self._persist()

    def clear(self, name: str) -> None:
        """Remove a key from the file. (Env-provided keys can't be cleared here.)"""
        if self.backend == "keyring":
            self._keyring_write(name, None)
            self.reload()
            return
        self._load()
        self._file_keys.pop(name.lower(), None)
        self._persist()

    def _persist(self) -> None:
        p = self.path
        p.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        content = _dump_toml(self._file_keys)
        fd, temporary = tempfile.mkstemp(prefix=f".{p.name}.", dir=p.parent)
        try:
            os.chmod(temporary, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
                handle.write(content)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, p)
            os.chmod(p, 0o600)
        finally:
            try:
                Path(temporary).unlink(missing_ok=True)
            except OSError:
                pass
        self.reload()


def redact(message: str) -> str:
    """Remove configured secret values from an error before it is stored or shown."""
    redacted = str(message)
    for key in KNOWN_KEYS:
        value = VAULT.get(key["name"])
        if value:
            redacted = redacted.replace(value, "[REDACTED]")
    return redacted


VAULT = KeyVault()
