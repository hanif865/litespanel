"""Password hashing and auth dependencies.

Uses the stdlib pbkdf2 (hashlib) rather than bcrypt so there's nothing to
compile on a fresh Windows or minimal VPS install — one less thing to break.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import time

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from .db import get_db
from .models import User

_ALGO = "sha256"
_ITERATIONS = 200_000

# --- Login brute-force throttle (in-memory; fine for a single-worker panel) ---
_MAX_ATTEMPTS = 5
_WINDOW_SECONDS = 300  # lock out for 5 minutes after 5 failures
_failed_logins: dict[str, list[float]] = {}


def client_ip(request: Request) -> str:
    """Real client IP, honoring the reverse proxy's X-Forwarded-For."""
    xff = request.headers.get("x-forwarded-for")
    if xff:
        return xff.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def login_throttled(key: str) -> bool:
    now = time.time()
    recent = [t for t in _failed_logins.get(key, []) if now - t < _WINDOW_SECONDS]
    _failed_logins[key] = recent
    return len(recent) >= _MAX_ATTEMPTS


def record_login_failure(key: str) -> None:
    _failed_logins.setdefault(key, []).append(time.time())


def clear_login_failures(key: str) -> None:
    _failed_logins.pop(key, None)


def generate_recovery_codes(n: int = 10) -> list[str]:
    """Human-friendly one-time backup codes (shown once at enrollment)."""
    # 5 bytes -> 8 base32 chars; grouped as XXXX-XXXX for readability.
    codes = []
    for _ in range(n):
        raw = base64.b32encode(secrets.token_bytes(5)).decode("ascii").rstrip("=")
        codes.append(f"{raw[:4]}-{raw[4:8]}")
    return codes


def hash_recovery_code(code: str) -> str:
    """SHA-256 of a normalized recovery code. These are already high-entropy,
    so a fast hash is fine (unlike passwords, which need pbkdf2)."""
    norm = code.strip().upper().replace(" ", "").replace("-", "")
    return hashlib.sha256(norm.encode()).hexdigest()


def check_and_consume_recovery_code(codes: list[str], attempt: str) -> tuple[bool, list[str]]:
    """If `attempt` matches a stored hash, return (True, codes-without-it).
    Recovery codes are single-use, so a match is removed from the list."""
    target = hash_recovery_code(attempt)
    for i, stored in enumerate(codes or []):
        if hmac.compare_digest(stored, target):
            remaining = list(codes[:i]) + list(codes[i + 1:])
            return True, remaining
    return False, list(codes or [])


def hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    dk = hashlib.pbkdf2_hmac(_ALGO, password.encode(), bytes.fromhex(salt), _ITERATIONS)
    return f"pbkdf2_{_ALGO}${_ITERATIONS}${salt}${dk.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        _, iterations, salt, expected = stored.split("$")
        dk = hashlib.pbkdf2_hmac(_ALGO, password.encode(), bytes.fromhex(salt), int(iterations))
        return hmac.compare_digest(dk.hex(), expected)
    except (ValueError, AttributeError):
        return False


def current_user(request: Request, db: Session = Depends(get_db)) -> User:
    """Dependency: resolve the logged-in user from the session, or 401."""
    user_id = request.session.get("user_id")
    if user_id is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")
    user = db.get(User, user_id)
    if user is None or user.suspended:
        request.session.clear()
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")
    return user


def require_manager(user: User = Depends(current_user)) -> User:
    """Dependency: only admins and resellers may pass (for the User Manager)."""
    if user.role not in ("admin", "reseller"):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admins and resellers only.")
    return user


def require_admin(user: User = Depends(current_user)) -> User:
    """Dependency: only full admins. For system-level actions (installing apt
    packages, the Node.js runtime) that shell out as root — never resellers."""
    if user.role != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admins only.")
    return user


def authenticate(db: Session, username: str, password: str) -> User | None:
    user = db.scalar(select(User).where(User.username == username))
    if user and verify_password(password, user.password_hash):
        return user
    return None


# --- Webmail single sign-on ------------------------------------------------
# The "Check Email" button opens a mailbox in Roundcube without asking for the
# password again. The panel never stores the mailbox password, so instead of
# handing one over it signs a short-lived token naming the mailbox; a Roundcube
# plugin verifies the signature with the same shared secret and logs the user in
# through a Dovecot master user. Secret unset (mail stack not installed) -> the
# caller falls back to the plain webmail login page.
_SSO_TTL_SECONDS = 60


def make_webmail_sso_token(address: str, secret: str, ttl: int = _SSO_TTL_SECONDS) -> str:
    """Sign `<address>|<expiry>` so Roundcube's panel_sso plugin can trust it.

    Returns `base64url(payload).hmac_sha256_hex`. Short-lived (60s) and carried
    once in the redirect URL — the plugin also rejects a token it has already
    seen, so a leaked URL can't be replayed after use.
    """
    payload = f"{address}|{int(time.time()) + ttl}".encode()
    sig = hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()
    b64 = base64.urlsafe_b64encode(payload).decode().rstrip("=")
    return f"{b64}.{sig}"
