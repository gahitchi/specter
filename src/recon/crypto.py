"""Optional passphrase encryption for investigation exports."""

from __future__ import annotations

import os

_MAGIC = b"OSINTRECON1\x00"
_SALT_BYTES = 16
_NONCE_BYTES = 12


def _primitives():
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
    except ImportError as exc:
        raise RuntimeError(
            "encrypted exports require the 'secure' optional dependency"
        ) from exc
    return AESGCM, Scrypt


def _key(passphrase: str, salt: bytes) -> bytes:
    if len(passphrase) < 12:
        raise ValueError("export passphrase must contain at least 12 characters")
    _aesgcm, scrypt = _primitives()
    return scrypt(salt=salt, length=32, n=2**15, r=8, p=1).derive(
        passphrase.encode("utf-8")
    )


def encrypt(data: bytes, passphrase: str) -> bytes:
    aesgcm, _scrypt = _primitives()
    salt = os.urandom(_SALT_BYTES)
    nonce = os.urandom(_NONCE_BYTES)
    ciphertext = aesgcm(_key(passphrase, salt)).encrypt(nonce, data, _MAGIC)
    return _MAGIC + salt + nonce + ciphertext


def decrypt(data: bytes, passphrase: str) -> bytes:
    aesgcm, _scrypt = _primitives()
    if not data.startswith(_MAGIC):
        raise ValueError("not an osint-recon encrypted export")
    offset = len(_MAGIC)
    salt = data[offset:offset + _SALT_BYTES]
    nonce = data[offset + _SALT_BYTES:offset + _SALT_BYTES + _NONCE_BYTES]
    ciphertext = data[offset + _SALT_BYTES + _NONCE_BYTES:]
    if len(salt) != _SALT_BYTES or len(nonce) != _NONCE_BYTES or not ciphertext:
        raise ValueError("encrypted export is truncated")
    return aesgcm(_key(passphrase, salt)).decrypt(nonce, ciphertext, _MAGIC)
