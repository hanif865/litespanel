"""Email account management — create mailboxes per domain."""
from __future__ import annotations

import re

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import RedirectResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..db import get_db
from ..models import Domain, EmailAccount, User
from ..limits import email_limit_reached
from ..providers import get_provider
from ..security import current_user
from ..web import templates

router = APIRouter(prefix="/email", tags=["email"])

_LOCAL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9._-]{0,62}[a-z0-9])?$")


def _flash(request: Request, message: str) -> None:
    request.session["flash"] = message


@router.get("")
def list_email(
    request: Request,
    domain_id: int | None = None,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    domains = db.scalars(
        select(Domain).where(Domain.owner_id == user.id).order_by(Domain.name)
    ).all()
    flash = request.session.pop("flash", None)
    ctx = {"user": user, "domains": domains, "active": "email", "flash": flash,
           "selected": None, "accounts": []}

    if domains:
        selected = db.get(Domain, domain_id) if domain_id else domains[0]
        if selected is None or selected.owner_id != user.id:
            selected = domains[0]
        accounts = db.scalars(
            select(EmailAccount).where(EmailAccount.domain_id == selected.id).order_by(EmailAccount.local_part)
        ).all()
        ctx.update({"selected": selected, "accounts": accounts})

    return templates.TemplateResponse(request, "email.html", ctx)


@router.post("/create")
def create_email(
    request: Request,
    domain_id: int = Form(...),
    local_part: str = Form(...),
    password: str = Form(...),
    quota_mb: int = Form(250),
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    domain = db.get(Domain, domain_id)
    if domain is None or domain.owner_id != user.id:
        _flash(request, "❌ Domain not found.")
        return RedirectResponse("/email", status_code=303)

    if email_limit_reached(db, user):
        _flash(request, f"❌ Email account limit reached ({user.max_email}).")
        return RedirectResponse(f"/email?domain_id={domain_id}", status_code=303)
    local_part = local_part.strip().lower()
    if not _LOCAL_RE.match(local_part):
        _flash(request, "❌ Invalid mailbox name.")
        return RedirectResponse(f"/email?domain_id={domain_id}", status_code=303)
    if len(password) < 6:
        _flash(request, "❌ Password must be at least 6 characters.")
        return RedirectResponse(f"/email?domain_id={domain_id}", status_code=303)
    if db.scalar(select(EmailAccount).where(
        EmailAccount.domain_id == domain.id, EmailAccount.local_part == local_part
    )):
        _flash(request, f"❌ {local_part}@{domain.name} already exists.")
        return RedirectResponse(f"/email?domain_id={domain_id}", status_code=303)

    address = f"{local_part}@{domain.name}"
    get_provider().create_mailbox(address, password, quota_mb)
    db.add(EmailAccount(domain_id=domain.id, local_part=local_part, quota_mb=quota_mb))
    db.commit()
    _flash(request, f"✅ Mailbox {address} created ({quota_mb} MB quota).")
    return RedirectResponse(f"/email?domain_id={domain_id}", status_code=303)


@router.post("/{account_id}/delete")
def delete_email(
    request: Request,
    account_id: int,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    account = db.get(EmailAccount, account_id)
    if account is None or account.domain.owner_id != user.id:
        _flash(request, "❌ Mailbox not found.")
        return RedirectResponse("/email", status_code=303)
    domain_id = account.domain_id
    address = account.address
    get_provider().delete_mailbox(address)
    db.delete(account)
    db.commit()
    _flash(request, f"🗑️ Mailbox {address} deleted.")
    return RedirectResponse(f"/email?domain_id={domain_id}", status_code=303)
