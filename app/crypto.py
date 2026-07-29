"""Lightweight reversible encryption for secrets stored at rest.

Used to keep MySQL user passwords in the panel DB confidential so the Database
Manager can auto-login to phpMyAdmin as a database's own scoped user (like
cPanel/Softaculous) without prompting for credentials.

This is a stdlib-only stream cipher (HMAC-SHA256 in counter mode) keyed off
`PANEL_SECRET_KEY`. It provides at-rest confidentiality — enough given the panel
DB is already root-only — but is not authenticated encryption. Set a stable
`PANEL_SECRET_KEY` in production (the installer does) or stored values won't
decrypt after a restart.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import os

from . import config

_NONCE_LEN = 16


def _keystream(nonce: bytes, length: int) -> bytes:
    key = hashlib.sha256(config.SECRET_KEY.encode()).digest()
    out = bytearray()
    counter = 0
    while len(out) < length:
        block = hmac.new(key, nonce + counter.to_bytes(4, "big"), hashlib.sha256).digest()
        out.extend(block)
        counter += 1
    return bytes(out[:length])


def encrypt(plaintext: str) -> str:
    data = plaintext.encode()
    nonce = os.urandom(_NONCE_LEN)
    ks = _keystream(nonce, len(data))
    ct = bytes(a ^ b for a, b in zip(data, ks))
    return base64.urlsafe_b64encode(nonce + ct).decode()


def decrypt(token: str | None) -> str | None:
    if not token:
        return None
    try:
        raw = base64.urlsafe_b64decode(token.encode())
        nonce, ct = raw[:_NONCE_LEN], raw[_NONCE_LEN:]
        ks = _keystream(nonce, len(ct))
        return bytes(a ^ b for a, b in zip(ct, ks)).decode()
    except Exception:  # noqa: BLE001 — corrupt/foreign token, treat as unavailable
        return None
