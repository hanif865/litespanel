"""Email forwarders — forward mail from an address to another."""
from __future__ import annotations

import re

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import RedirectResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..db import get_db
from ..models import Domain, EmailForwarder, User
from ..providers import get_provider
from ..security import current_user
from ..web import templates

router = APIRouter(prefix="/forwarders", tags=["forwarders"])

_SOURCE_RE = re.compile(r"^(\*|[a-z0-9](?:[a-z0-9._-]{0,62}[a-z0-9])?)$")
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def _flash(request: Request, message: str) -> None:
    request.session["flash"] = message


def _sync(db: Session, domain: Domain) -> None:
    fwds = db.scalars(select(EmailForwarder).where(EmailForwarder.domain_id == domain.id)).all()
    get_provider().sync_forwarders(domain.name, [(f.source, f.destination) for f in fwds])


@router.get("")
def list_forwarders(
    request: Request,
    domain_id: int | None = None,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    domains = db.scalars(select(Domain).where(Domain.owner_id == user.id).order_by(Domain.name)).all()
    flash = request.session.pop("flash", None)
    ctx = {"user": user, "domains": domains, "active": "forwarders", "flash": flash,
           "selected": None, "forwarders": []}
    if domains:
        selected = db.get(Domain, domain_id) if domain_id else domains[0]
        if selected is None or selected.owner_id != user.id:
            selected = domains[0]
        fwds = db.scalars(
            select(EmailForwarder).where(EmailForwarder.domain_id == selected.id).order_by(EmailForwarder.source)
        ).all()
        ctx.update({"selected": selected, "forwarders": fwds})
    return templates.TemplateResponse(request, "forwarders.html", ctx)


@router.post("/create")
def create_forwarder(
    request: Request,
    domain_id: int = Form(...),
    source: str = Form(...),
    destination: str = Form(...),
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    domain = db.get(Domain, domain_id)
    if domain is None or domain.owner_id != user.id:
        _flash(request, "❌ Domain not found.")
        return RedirectResponse("/forwarders", status_code=303)

    source = source.strip().lower()
    destination = destination.strip().lower()
    if not _SOURCE_RE.match(source):
        _flash(request, "❌ Invalid source (mailbox name or * for catch-all).")
        return RedirectResponse(f"/forwarders?domain_id={domain_id}", status_code=303)
    if not _EMAIL_RE.match(destination):
        _flash(request, "❌ Destination must be a valid email address.")
        return RedirectResponse(f"/forwarders?domain_id={domain_id}", status_code=303)

    db.add(EmailForwarder(domain_id=domain.id, source=source, destination=destination))
    db.commit()
    _sync(db, domain)
    _flash(request, f"✅ {source}@{domain.name} → {destination}")
    return RedirectResponse(f"/forwarders?domain_id={domain_id}", status_code=303)


@router.post("/{fwd_id}/delete")
def delete_forwarder(
    request: Request,
    fwd_id: int,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    fwd = db.get(EmailForwarder, fwd_id)
    if fwd is None or fwd.domain.owner_id != user.id:
        _flash(request, "❌ Forwarder not found.")
        return RedirectResponse("/forwarders", status_code=303)
    domain = fwd.domain
    db.delete(fwd)
    db.commit()
    _sync(db, domain)
    _flash(request, "🗑️ Forwarder removed.")
    return RedirectResponse(f"/forwarders?domain_id={domain.id}", status_code=303)
