"""Cloudflare DNS — per-account (client-managed).

Each hosting account connects its own Cloudflare account by saving a scoped API
token here. Once enabled, every DNS change the account makes — subdomains and
Zone Editor edits — is mirrored to *their* Cloudflare, so records go live
automatically (see app/cloudflare.py). Every route is scoped to the logged-in
user's own account: a client only ever sees and touches their own token and
their own domains.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import RedirectResponse
from sqlalchemy import func, select
from starlette.concurrency import run_in_threadpool
from sqlalchemy.orm import Session

from .. import cloudflare
from ..db import get_db
from ..models import Domain, User
from ..security import current_user
from ..web import templates

router = APIRouter(prefix="/cloudflare", tags=["cloudflare"])


def _flash(request: Request, message: str) -> None:
    request.session["flash"] = message


@router.get("")
def page(request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)):
    flash = request.session.pop("flash", None)
    zone_count = db.scalar(
        select(func.count()).select_from(Domain).where(Domain.owner_id == user.id)
    )
    return templates.TemplateResponse(
        request, "cloudflare.html",
        {"user": user, "active": "cloudflare", "flash": flash,
         "cf": cloudflare.settings_for(db, user.id), "zone_count": zone_count},
    )


@router.post("/save")
async def save(
    request: Request, enabled: str = Form(""), proxied: str = Form(""),
    api_token: str = Form(""),
    user: User = Depends(current_user), db: Session = Depends(get_db),
):
    want_on = enabled.lower() in ("1", "true", "on", "yes")
    want_proxied = proxied.lower() in ("1", "true", "on", "yes")
    token = api_token.strip()
    # Enabling without any token (none saved) is meaningless — block it early.
    if want_on and not token and not cloudflare.settings_for(db, user.id)["token_set"]:
        _flash(request, "❌ Paste a Cloudflare API token before enabling sync.")
        return RedirectResponse("/cloudflare", status_code=303)
    cloudflare.save_cred(db, user.id, enabled=want_on, token=token or None, proxied=want_proxied)
    if token:
        ok, message = await run_in_threadpool(cloudflare.verify_owner, db, user.id)
        _flash(request, ("✅ Saved. " if ok else "⚠️ Saved, but ") + message)
    else:
        _flash(request, "✅ Cloudflare settings saved.")
    return RedirectResponse("/cloudflare", status_code=303)


@router.post("/test")
async def test(request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)):
    ok, message = await run_in_threadpool(cloudflare.verify_owner, db, user.id)
    _flash(request, ("✅ " if ok else "❌ ") + message)
    return RedirectResponse("/cloudflare", status_code=303)


@router.post("/disconnect")
def disconnect(request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)):
    cloudflare.clear_cred(db, user.id)
    _flash(request, "🗑️ Cloudflare token removed and sync turned off.")
    return RedirectResponse("/cloudflare", status_code=303)


@router.post("/sync-all")
async def sync_all(request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)):
    if not cloudflare.enabled_for(db, user.id):
        _flash(request, "❌ Save a token and enable auto-sync first.")
        return RedirectResponse("/cloudflare", status_code=303)
    ok_n, fail_n, notes = await run_in_threadpool(cloudflare.sync_all_for, db, user.id)
    summary = f"Synced {ok_n} zone(s), {fail_n} skipped/failed."
    if notes:
        summary += " " + " | ".join(notes[:4])
    _flash(request, ("✅ " if fail_n == 0 else "⚠️ ") + summary)
    return RedirectResponse("/cloudflare", status_code=303)
