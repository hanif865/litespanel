"""IP Blocker — admin-only page to block IPs host-wide and review auto-bans.

cPanel's IP Blocker lets an admin deny a specific IP/CIDR at the host and lift
automatic bans. We mirror that on one page: a manual permanent blocklist (blanket
ufw deny rules, via provider.block_ip / unblock_ip) plus the automatic fail2ban
bans (reusing the existing fail2ban provider methods) aggregated across all jails.

Admin-only, like the Firewall page — blocking an IP affects the whole host.
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

router = APIRouter(prefix="/ip-blocker", tags=["ip-blocker"])


def _flash(request: Request, message: str) -> None:
    request.session["flash"] = message


def _redirect() -> RedirectResponse:
    return RedirectResponse("/ip-blocker", status_code=303)


@router.get("")
def ip_blocker_home(
    request: Request,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    if user.role != "admin":
        _flash(request, "❌ IP Blocker is an admin-only feature.")
        return RedirectResponse("/", status_code=303)

    flash = request.session.pop("flash", None)
    provider = get_provider()

    fw = provider.firewall_status()
    blocked = provider.list_blocked_ips()
    f2b = provider.fail2ban_status()
    jails = [
        {"name": name, "banned": provider.list_banned_ips(name)}
        for name in f2b.get("jails", [])
    ]

    return templates.TemplateResponse(
        request,
        "ip_blocker.html",
        {
            "user": user,
            "is_admin": True,
            "fw": fw,
            "blocked": blocked,
            "f2b": f2b,
            "jails": jails,
            "active": "ip_blocker",
            "flash": flash,
        },
    )


@router.post("/block")
async def block(
    request: Request,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    if user.role != "admin":
        _flash(request, "❌ Only an admin can block IPs.")
        return _redirect()
    form = await request.form()
    ip = (form.get("ip") or "").strip()
    comment = (form.get("comment") or "").strip() or None
    if not ip:
        _flash(request, "❌ An IP or CIDR is required.")
        return _redirect()
    ok, message = get_provider().block_ip(ip, comment)
    _flash(request, ("✅ " if ok else "❌ ") + message)
    return _redirect()


@router.post("/unblock")
async def unblock(
    request: Request,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    if user.role != "admin":
        _flash(request, "❌ Only an admin can unblock IPs.")
        return _redirect()
    form = await request.form()
    ip = (form.get("ip") or "").strip()
    if not ip:
        _flash(request, "❌ An IP is required.")
        return _redirect()
    ok, message = get_provider().unblock_ip(ip)
    _flash(request, ("✅ " if ok else "❌ ") + message)
    return _redirect()


@router.post("/fail2ban/unban")
async def unban(
    request: Request,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    if user.role != "admin":
        _flash(request, "❌ Only an admin can lift bans.")
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
