"""Firewall & security — admin-only ufw rules and fail2ban ban management.

Security is an admin feature: only an admin can toggle the host firewall, add
or delete ufw rules, or ban/unban IPs through fail2ban. The provider layer does
the real work (ufw / fail2ban-client on Linux, inspectable JSON in the demo);
this router just validates form input and renders state. Enabling ufw applies
packet filtering to the whole host, so the UI warns before the toggle.
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

router = APIRouter(prefix="/firewall", tags=["firewall"])


def _flash(request: Request, message: str) -> None:
    request.session["flash"] = message


def _redirect() -> RedirectResponse:
    return RedirectResponse("/firewall", status_code=303)


@router.get("")
def firewall_home(
    request: Request,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    if user.role != "admin":
        _flash(request, "❌ Firewall & security is an admin-only feature.")
        return RedirectResponse("/", status_code=303)

    flash = request.session.pop("flash", None)
    provider = get_provider()

    fw = provider.firewall_status()
    rules = provider.list_firewall_rules()
    f2b = provider.fail2ban_status()
    jails = [
        {"name": name, "banned": provider.list_banned_ips(name)}
        for name in f2b.get("jails", [])
    ]

    return templates.TemplateResponse(
        request,
        "firewall.html",
        {
            "user": user,
            "is_admin": True,
            "fw": fw,
            "rules": rules,
            "f2b": f2b,
            "jails": jails,
            "active": "firewall",
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
        _flash(request, "❌ Only an admin can change the firewall.")
        return _redirect()
    form = await request.form()
    enabled = (form.get("enabled") or "").strip() == "1"
    ok, message = get_provider().set_firewall_enabled(enabled)
    _flash(request, ("✅ " if ok else "❌ ") + message)
    return _redirect()


@router.post("/rules/add")
async def add_rule(
    request: Request,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    if user.role != "admin":
        _flash(request, "❌ Only an admin can add firewall rules.")
        return _redirect()
    form = await request.form()
    port_raw = (form.get("port") or "").strip()
    proto = (form.get("proto") or "tcp").strip().lower()
    action = (form.get("action") or "allow").strip().lower()
    source = (form.get("source") or "").strip() or None

    try:
        port = int(port_raw)
    except ValueError:
        _flash(request, "❌ Port must be a number.")
        return _redirect()
    if not (1 <= port <= 65535):
        _flash(request, "❌ Port must be between 1 and 65535.")
        return _redirect()
    if proto not in ("tcp", "udp"):
        _flash(request, "❌ Protocol must be tcp or udp.")
        return _redirect()
    if action not in ("allow", "deny"):
        _flash(request, "❌ Action must be allow or deny.")
        return _redirect()

    ok, message = get_provider().add_firewall_rule(port, proto, action, source)
    _flash(request, ("✅ " if ok else "❌ ") + message)
    return _redirect()


@router.post("/rules/delete")
async def delete_rule(
    request: Request,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    if user.role != "admin":
        _flash(request, "❌ Only an admin can delete firewall rules.")
        return _redirect()
    form = await request.form()
    try:
        num = int((form.get("num") or "").strip())
    except ValueError:
        _flash(request, "❌ Invalid rule number.")
        return _redirect()
    ok, message = get_provider().delete_firewall_rule(num)
    _flash(request, ("✅ " if ok else "❌ ") + message)
    return _redirect()


@router.post("/fail2ban/ban")
async def ban(
    request: Request,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    if user.role != "admin":
        _flash(request, "❌ Only an admin can ban IPs.")
        return _redirect()
    form = await request.form()
    ip = (form.get("ip") or "").strip()
    jail = (form.get("jail") or "").strip()
    if not ip or not jail:
        _flash(request, "❌ IP and jail are required.")
        return _redirect()
    ok, message = get_provider().ban_ip(ip, jail)
    _flash(request, ("✅ " if ok else "❌ ") + message)
    return _redirect()


@router.post("/fail2ban/unban")
async def unban(
    request: Request,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    if user.role != "admin":
        _flash(request, "❌ Only an admin can unban IPs.")
        return _redirect()
    form = await request.form()
    ip = (form.get("ip") or "").strip()
    jail = (form.get("jail") or "").strip()
    if not ip or not jail:
        _flash(request, "❌ IP and jail are required.")
        return _redirect()
    ok, message = get_provider().unban_ip(ip, jail)
    _flash(request, ("✅ " if ok else "❌ ") + message)
    return _redirect()
