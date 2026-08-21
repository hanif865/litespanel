"""Email autoresponders — automatic replies (e.g. out-of-office)."""
from __future__ import annotations

import re

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import RedirectResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..db import get_db
from ..models import Autoresponder, Domain, User
from ..security import current_user
from ..web import templates
from .mailfilters import resync_mailbox_sieve

router = APIRouter(prefix="/autoresponders", tags=["autoresponders"])

_LOCAL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9._-]{0,62}[a-z0-9])?$")


def _flash(request: Request, message: str) -> None:
    request.session["flash"] = message


@router.get("")
def list_autoresponders(
    request: Request,
    domain_id: int | None = None,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    domains = db.scalars(select(Domain).where(Domain.owner_id == user.id).order_by(Domain.name)).all()
    flash = request.session.pop("flash", None)
    ctx = {"user": user, "domains": domains, "active": "autoresponders", "flash": flash,
           "selected": None, "responders": []}
    if domains:
        selected = db.get(Domain, domain_id) if domain_id else domains[0]
        if selected is None or selected.owner_id != user.id:
            selected = domains[0]
        responders = db.scalars(
            select(Autoresponder).where(Autoresponder.domain_id == selected.id).order_by(Autoresponder.local_part)
        ).all()
        ctx.update({"selected": selected, "responders": responders})
    return templates.TemplateResponse(request, "autoresponders.html", ctx)


@router.post("/create")
def create_autoresponder(
    request: Request,
    domain_id: int = Form(...),
    local_part: str = Form(...),
    subject: str = Form(...),
    body: str = Form(...),
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    domain = db.get(Domain, domain_id)
    if domain is None or domain.owner_id != user.id:
        _flash(request, "❌ Domain not found.")
        return RedirectResponse("/autoresponders", status_code=303)

    local_part = local_part.strip().lower()
    subject = subject.strip()[:255]
    body = body.strip()[:2000]
    if not _LOCAL_RE.match(local_part):
        _flash(request, "❌ Invalid mailbox name.")
        return RedirectResponse(f"/autoresponders?domain_id={domain_id}", status_code=303)
    if not subject or not body:
        _flash(request, "❌ Subject and message are required.")
        return RedirectResponse(f"/autoresponders?domain_id={domain_id}", status_code=303)
    if db.scalar(select(Autoresponder).where(
        Autoresponder.domain_id == domain.id, Autoresponder.local_part == local_part
    )):
        _flash(request, f"❌ An autoresponder for {local_part}@{domain.name} already exists.")
        return RedirectResponse(f"/autoresponders?domain_id={domain_id}", status_code=303)

    ar = Autoresponder(domain_id=domain.id, local_part=local_part, subject=subject, body=body, enabled=True)
    db.add(ar)
    db.commit()
    resync_mailbox_sieve(db, domain, local_part)
    _flash(request, f"✅ Autoresponder for {ar.address} created.")
    return RedirectResponse(f"/autoresponders?domain_id={domain_id}", status_code=303)


@router.post("/{ar_id}/toggle")
def toggle_autoresponder(
    request: Request,
    ar_id: int,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    ar = db.get(Autoresponder, ar_id)
    if ar is None or ar.domain.owner_id != user.id:
        _flash(request, "❌ Not found.")
        return RedirectResponse("/autoresponders", status_code=303)
    ar.enabled = not ar.enabled
    db.commit()
    resync_mailbox_sieve(db, ar.domain, ar.local_part)
    _flash(request, f"{'▶️ Enabled' if ar.enabled else '⏸️ Disabled'} autoresponder for {ar.address}.")
    return RedirectResponse(f"/autoresponders?domain_id={ar.domain_id}", status_code=303)


@router.post("/{ar_id}/delete")
def delete_autoresponder(
    request: Request,
    ar_id: int,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    ar = db.get(Autoresponder, ar_id)
    if ar is None or ar.domain.owner_id != user.id:
        _flash(request, "❌ Not found.")
        return RedirectResponse("/autoresponders", status_code=303)
    domain, local_part, domain_id, address = ar.domain, ar.local_part, ar.domain_id, ar.address
    db.delete(ar)
    db.commit()
    resync_mailbox_sieve(db, domain, local_part)
    _flash(request, f"🗑️ Autoresponder for {address} removed.")
    return RedirectResponse(f"/autoresponders?domain_id={domain_id}", status_code=303)
