"""Subdomain management — e.g. blog.example.com.

A subdomain's document root lives inside its parent's public_html (cPanel's
default), so its files are managed through the parent domain's File Manager.
"""
from __future__ import annotations

import re
from pathlib import Path

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import RedirectResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import config
from ..accounts import account_home
from ..db import get_db
from ..models import DnsRecord, Domain, Subdomain, User
from ..providers import get_provider
from ..security import current_user
from ..web import templates

router = APIRouter(prefix="/subdomains", tags=["subdomains"])

_LABEL_RE = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")


def _flash(request: Request, message: str) -> None:
    request.session["flash"] = message


def _zone_payload(domain: Domain) -> list[dict]:
    """Serialize a domain's DNS records into the shape sync_zone expects."""
    return [
        {"type": r.rtype, "name": r.name, "value": r.value,
         "ttl": r.ttl, "priority": r.priority}
        for r in domain.dns_records
    ]


@router.get("")
def list_subdomains(request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)):
    domains = db.scalars(
        select(Domain).where(Domain.owner_id == user.id).order_by(Domain.name)
    ).all()
    subs = db.scalars(
        select(Subdomain).join(Domain).where(Domain.owner_id == user.id).order_by(Subdomain.fqdn)
    ).all()
    flash = request.session.pop("flash", None)
    return templates.TemplateResponse(
        request,
        "subdomains.html",
        {"user": user, "domains": domains, "subs": subs, "active": "subdomains", "flash": flash},
    )


@router.post("/create")
def create_subdomain(
    request: Request,
    label: str = Form(...),
    parent_id: int = Form(...),
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    label = label.strip().lower()
    parent = db.get(Domain, parent_id)
    if parent is None or parent.owner_id != user.id:
        _flash(request, "❌ Parent domain not found.")
        return RedirectResponse("/subdomains", status_code=303)
    if not _LABEL_RE.match(label):
        _flash(request, "❌ Invalid subdomain label (letters, digits, hyphen).")
        return RedirectResponse("/subdomains", status_code=303)

    fqdn = f"{label}.{parent.name}"
    if db.scalar(select(Subdomain).where(Subdomain.fqdn == fqdn)):
        _flash(request, f"❌ {fqdn} already exists.")
        return RedirectResponse("/subdomains", status_code=303)

    # Subdomain files live inside the parent's docroot, i.e. under the same
    # isolated account. Ensure that account exists and reuse its system_user.
    account_home(db, user)
    docroot = Path(parent.docroot) / label
    get_provider().create_subdomain(fqdn, docroot, parent.php_version, user.system_user)
    get_provider().reload_web()
    db.add(Subdomain(
        label=label, fqdn=fqdn, parent_id=parent.id,
        docroot=str(docroot), php_version=parent.php_version,
    ))

    # Publish DNS so the subdomain actually resolves. Without an A record the
    # zone never learns about the label and clients get NXDOMAIN. The panel DB
    # is the source of truth, so add the record then re-sync the whole zone.
    if not db.scalar(
        select(DnsRecord).where(
            DnsRecord.domain_id == parent.id,
            DnsRecord.rtype == "A",
            DnsRecord.name == label,
        )
    ):
        db.add(DnsRecord(
            domain_id=parent.id, rtype="A", name=label,
            value=config.SERVER_IP, ttl=14400,
        ))
    db.flush()
    get_provider().sync_zone(parent.name, _zone_payload(parent))
    db.commit()
    _flash(
        request,
        f"✅ {fqdn} created. DNS A record → {config.SERVER_IP} added; public "
        "resolution requires this domain's nameservers to point here.",
    )
    return RedirectResponse("/subdomains", status_code=303)


@router.post("/{sub_id}/delete")
def delete_subdomain(
    request: Request,
    sub_id: int,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    sub = db.get(Subdomain, sub_id)
    if sub is None or sub.parent.owner_id != user.id:
        _flash(request, "❌ Subdomain not found.")
        return RedirectResponse("/subdomains", status_code=303)
    get_provider().remove_subdomain(sub.fqdn)
    get_provider().reload_web()
    fqdn = sub.fqdn
    parent = sub.parent
    label = sub.label

    # Retract the published A record so the zone stops advertising the label.
    record = db.scalar(
        select(DnsRecord).where(
            DnsRecord.domain_id == parent.id,
            DnsRecord.rtype == "A",
            DnsRecord.name == label,
        )
    )
    if record is not None:
        db.delete(record)
    db.delete(sub)
    db.flush()
    get_provider().sync_zone(parent.name, _zone_payload(parent))
    db.commit()
    _flash(request, f"🗑️ {fqdn} removed.")
    return RedirectResponse("/subdomains", status_code=303)
