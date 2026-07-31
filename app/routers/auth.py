"""Login / logout."""
from __future__ import annotations

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy.orm import Session

from ..db import get_db
from ..models import User
from .. import crypto, totp
from ..security import (
    authenticate, check_and_consume_recovery_code, clear_login_failures, client_ip,
    login_throttled, record_login_failure,
)
from ..web import templates

router = APIRouter(tags=["auth"])


@router.get("/login", response_class=HTMLResponse)
def login_form(request: Request):
    if request.session.get("user_id"):
        return RedirectResponse("/", status_code=303)
    return templates.TemplateResponse(request, "login.html", {"error": None})


@router.post("/login", response_class=HTMLResponse)
def login_submit(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db),
):
    ip = client_ip(request)
    if login_throttled(ip):
        return templates.TemplateResponse(
            request, "login.html",
            {"error": "Too many failed attempts. Try again in a few minutes."},
            status_code=429,
        )

    user = authenticate(db, username, password)
    if user is None:
        record_login_failure(ip)
        return templates.TemplateResponse(
            request, "login.html", {"error": "Invalid username or password."}, status_code=401
        )
    if user.suspended:
        return templates.TemplateResponse(
            request, "login.html", {"error": "This account is suspended."}, status_code=403
        )
    clear_login_failures(ip)
    # New session id on privilege change (mitigates session fixation).
    request.session.clear()
    if user.totp_enabled:
        # Password was correct but 2FA is on: don't grant access yet. Park the
        # user id in a pending slot and require a code at /login/2fa.
        request.session["pending_2fa_user"] = user.id
        return RedirectResponse("/login/2fa", status_code=303)
    request.session["user_id"] = user.id
    return RedirectResponse("/", status_code=303)


@router.get("/login/2fa", response_class=HTMLResponse)
def twofa_form(request: Request):
    if request.session.get("user_id"):
        return RedirectResponse("/", status_code=303)
    if not request.session.get("pending_2fa_user"):
        return RedirectResponse("/login", status_code=303)
    return templates.TemplateResponse(request, "login_2fa.html", {"error": None})


@router.post("/login/2fa", response_class=HTMLResponse)
def twofa_submit(
    request: Request,
    code: str = Form(...),
    db: Session = Depends(get_db),
):
    pending_id = request.session.get("pending_2fa_user")
    if not pending_id:
        return RedirectResponse("/login", status_code=303)

    ip = client_ip(request)
    if login_throttled(ip):
        return templates.TemplateResponse(
            request, "login_2fa.html",
            {"error": "Too many attempts. Try again in a few minutes."},
            status_code=429,
        )

    user = db.get(User, pending_id)
    if user is None or user.suspended or not user.totp_enabled:
        request.session.clear()
        return RedirectResponse("/login", status_code=303)

    secret = crypto.decrypt(user.totp_secret_enc)
    ok = bool(secret) and totp.verify(secret, code)
    if not ok:
        # Fall back to a single-use recovery code.
        matched, remaining = check_and_consume_recovery_code(user.recovery_codes, code)
        if matched:
            user.recovery_codes = remaining
            db.commit()
            ok = True

    if not ok:
        record_login_failure(ip)
        return templates.TemplateResponse(
            request, "login_2fa.html", {"error": "Invalid authentication code."},
            status_code=401,
        )

    clear_login_failures(ip)
    request.session.clear()
    request.session["user_id"] = user.id
    return RedirectResponse("/", status_code=303)


@router.get("/logout")
def logout(request: Request):
    request.session.clear()
    return RedirectResponse("/login", status_code=303)
