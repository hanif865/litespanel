"""ModSecurity WAF — admin-only on/off toggle for the nginx web firewall.

ModSecurity is a Web Application Firewall that inspects every HTTP request and
blocks common attacks (SQLi, XSS, path traversal, …) using a rule set such as
the OWASP Core Rule Set. It filters traffic for the whole host, so — like the
Firewall and IP Blocker pages — this is admin-only. The provider does the real
work (rewrites the SecRuleEngine directive and reloads nginx on Linux,
inspectable JSON in the demo); this router validates the form and renders state.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session

from ..db import get_db
from ..models import User
from ..providers import get_provider
from ..security import current_user
from ..web import templates

router = APIRouter(prefix="/modsecurity", tags=["modsecurity"])


def _flash(request: Request, message: str) -> None:
    request.session["flash"] = message


def _redirect() -> RedirectResponse:
    return RedirectResponse("/modsecurity", status_code=303)


@router.get("")
def modsecurity_home(
    request: Request,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    if user.role != "admin":
        _flash(request, "❌ ModSecurity is an admin-only feature.")
        return RedirectResponse("/", status_code=303)

    flash = request.session.pop("flash", None)
    waf = get_provider().modsecurity_status()

    return templates.TemplateResponse(
        request,
        "modsecurity.html",
        {
            "user": user,
            "is_admin": True,
            "waf": waf,
            "active": "modsecurity",
            "flash": flash,
        },
    )


@router.post("/toggle")
async def toggle(
    request: Request,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    if user.role != "admin":
        _flash(request, "❌ Only an admin can change the WAF.")
        return _redirect()
    form = await request.form()
    enabled = (form.get("enabled") or "").strip() == "1"
    mode = (form.get("mode") or "On").strip()
    if mode not in ("On", "DetectionOnly"):
        mode = "On"
    ok, message = get_provider().set_modsecurity(enabled, mode)
    _flash(request, ("✅ " if ok else "❌ ") + message)
    return _redirect()
