"""Time-based one-time passwords (RFC 6238) — pure stdlib.

Like the rest of the panel's crypto (see security.py's pbkdf2 choice), this
avoids a compiled dependency so nothing breaks on a fresh Windows dev box or a
minimal Python 3.14 VPS. It implements exactly what an authenticator app
(Google Authenticator, Authy, 1Password, ...) expects: HMAC-SHA1, 6 digits, a
30-second step. The QR code shown during setup encodes the otpauth:// URI built
by provisioning_uri(); the app then generates the same codes verify() checks.
"""
from __future__ import annotations

import base64
import hmac
import secrets
import struct
import time
from hashlib import sha1
from urllib.parse import quote

_DIGITS = 6
_PERIOD = 30            # seconds per code
_ALLOWED_DRIFT = 1      # accept the previous/next step to tolerate clock skew


def generate_secret() -> str:
    """A fresh base32 shared secret (no padding) for a new enrollment."""
    # 20 random bytes -> 160 bits, the RFC 4226 recommended key length.
    return base64.b32encode(secrets.token_bytes(20)).decode("ascii").rstrip("=")


def _hotp(secret: str, counter: int) -> str:
    """RFC 4226 HOTP: the building block TOTP steps over time."""
    # base32 decode is case-insensitive and needs the padding we stripped off.
    key = base64.b32decode(secret.upper() + "=" * (-len(secret) % 8))
    digest = hmac.new(key, struct.pack(">Q", counter), sha1).digest()
    offset = digest[-1] & 0x0F
    code = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(code % (10 ** _DIGITS)).zfill(_DIGITS)


def now_code(secret: str, at: float | None = None) -> str:
    """The current code — used to render a fallback/testing value."""
    counter = int((at if at is not None else time.time()) // _PERIOD)
    return _hotp(secret, counter)


def verify(secret: str, code: str, at: float | None = None) -> bool:
    """True if `code` matches the current step (±1 for clock drift)."""
    code = (code or "").strip().replace(" ", "")
    if not code.isdigit() or len(code) != _DIGITS:
        return False
    counter = int((at if at is not None else time.time()) // _PERIOD)
    for drift in range(-_ALLOWED_DRIFT, _ALLOWED_DRIFT + 1):
        if hmac.compare_digest(_hotp(secret, counter + drift), code):
            return True
    return False


def provisioning_uri(secret: str, account: str, issuer: str) -> str:
    """otpauth:// URI an authenticator app scans from the setup QR code."""
    label = quote(f"{issuer}:{account}")
    params = (
        f"secret={secret}"
        f"&issuer={quote(issuer)}"
        f"&algorithm=SHA1&digits={_DIGITS}&period={_PERIOD}"
    )
    return f"otpauth://totp/{label}?{params}"


def qr_svg(data: str) -> str | None:
    """Render `data` as an inline SVG QR code, or None if qrcode isn't installed.

    Uses qrcode's SVG image factory, which is pure-Python (ElementTree) — no PIL
    or other compiled dependency, so it installs cleanly on Python 3.14. When the
    package is unavailable the caller falls back to showing the manual secret.
    """
    try:
        import io

        import qrcode
        import qrcode.image.svg as qrsvg
    except ImportError:
        return None
    img = qrcode.make(data, image_factory=qrsvg.SvgPathImage, box_size=10, border=2)
    buf = io.BytesIO()
    img.save(buf)
    return buf.getvalue().decode("utf-8")
