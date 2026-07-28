"""Login / logout."""
from __future__ import annotations

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy.orm import Session

from ..db import get_db
from ..security import (
    authenticate, clear_login_failures, client_ip, login_throttled, record_login_failure,
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
    request.session["user_id"] = user.id
    return RedirectResponse("/", status_code=303)


@router.get("/logout")
def logout(request: Request):
    request.session.clear()
    return RedirectResponse("/login", status_code=303)
