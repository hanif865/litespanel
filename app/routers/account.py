"""Account settings — password change and two-factor auth (self-service).

Every user can access /account/security to enable TOTP 2FA (scan a QR code, get
10 single-use recovery codes) or disable it (requires a current valid code).
Unlike the admin-only features (firewall, node, user manager), this is open to
all authenticated users so they can secure their own account.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy.orm import Session

from .. import config, crypto, totp
from ..db import get_db
from ..models import User
from ..security import current_user, generate_recovery_codes, hash_recovery_code
from ..web import templates

router = APIRouter(prefix="/account", tags=["account"])


def _flash(request: Request, message: str) -> None:
    request.session["flash"] = message


def _redirect() -> RedirectResponse:
    return RedirectResponse("/account/security", status_code=303)


@router.get("/security", response_class=HTMLResponse)
def security_home(
    request: Request,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    flash = request.session.pop("flash", None)
    # Pull setup state from the session if the user just enabled 2FA (so we can
    # show the recovery codes once — they're hashed at rest and unrecoverable).
    fresh_codes = request.session.pop("fresh_recovery_codes", None)
    return templates.TemplateResponse(
        request,
        "account_security.html",
        {
            "user": user,
            "flash": flash,
            "fresh_codes": fresh_codes,
            "recovery_count": len(user.recovery_codes) if user.totp_enabled else 0,
            "active": "account",
        },
    )


@router.post("/security/2fa/enable")
async def enable_2fa(
    request: Request,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    """Step 1: generate secret + QR, park it in session, redirect to confirm."""
    if user.totp_enabled:
        _flash(request, "❌ Two-factor authentication is already enabled.")
        return _redirect()
    secret = totp.generate_secret()
    uri = totp.provisioning_uri(secret, user.username, config.APP_NAME)
    request.session["pending_totp_secret"] = secret
    request.session["pending_totp_uri"] = uri
    return RedirectResponse("/account/security/2fa/setup", status_code=303)


@router.get("/security/2fa/setup", response_class=HTMLResponse)
def setup_2fa(
    request: Request,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    """Step 2: show QR + manual secret, ask for a code to confirm the user scanned it."""
    secret = request.session.get("pending_totp_secret")
    uri = request.session.get("pending_totp_uri")
    if not secret or not uri:
        return RedirectResponse("/account/security", status_code=303)
    error = request.session.pop("totp_setup_error", None)
    qr_svg = totp.qr_svg(uri)
    return templates.TemplateResponse(
        request,
        "account_2fa_setup.html",
        {
            "user": user,
            "secret": secret,
            "uri": uri,
            "qr_svg": qr_svg,
            "error": error,
        },
    )


@router.post("/security/2fa/confirm")
async def confirm_2fa(
    request: Request,
    code: str = Form(...),
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    """Step 3: verify the code, commit the secret, generate recovery codes."""
    secret = request.session.get("pending_totp_secret")
    if not secret:
        return RedirectResponse("/account/security", status_code=303)
    if not totp.verify(secret, code):
        request.session["totp_setup_error"] = "Invalid code. Check your app and try again."
        return RedirectResponse("/account/security/2fa/setup", status_code=303)

    # Code is good — enable 2FA and generate recovery codes.
    recovery_plain = generate_recovery_codes()
    user.totp_secret_enc = crypto.encrypt(secret)
    user.totp_enabled = True
    user.recovery_codes = [hash_recovery_code(c) for c in recovery_plain]
    db.commit()

    # Clean up session setup state and stash the plain codes so /security shows them once.
    request.session.pop("pending_totp_secret", None)
    request.session.pop("pending_totp_uri", None)
    request.session["fresh_recovery_codes"] = recovery_plain
    _flash(request, "✅ Two-factor authentication is now enabled.")
    return _redirect()


@router.post("/security/2fa/disable")
async def disable_2fa(
    request: Request,
    code: str = Form(...),
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    if not user.totp_enabled:
        _flash(request, "❌ Two-factor authentication is not enabled.")
        return _redirect()
    secret = crypto.decrypt(user.totp_secret_enc)
    if not secret or not totp.verify(secret, code):
        _flash(request, "❌ Invalid code — cannot disable 2FA without verification.")
        return _redirect()

    user.totp_enabled = False
    user.totp_secret_enc = None
    user.recovery_codes = []
    db.commit()
    _flash(request, "✅ Two-factor authentication has been disabled.")
    return _redirect()


@router.post("/security/recovery-codes/regenerate")
async def regenerate_recovery(
    request: Request,
    code: str = Form(...),
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    if not user.totp_enabled:
        _flash(request, "❌ Two-factor authentication is not enabled.")
        return _redirect()
    secret = crypto.decrypt(user.totp_secret_enc)
    if not secret or not totp.verify(secret, code):
        _flash(request, "❌ Invalid code — cannot regenerate recovery codes without verification.")
        return _redirect()

    recovery_plain = generate_recovery_codes()
    user.recovery_codes = [hash_recovery_code(c) for c in recovery_plain]
    db.commit()
    request.session["fresh_recovery_codes"] = recovery_plain
    _flash(request, "✅ New recovery codes generated. Save them now — they won't be shown again.")
    return _redirect()
