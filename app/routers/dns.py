"""DNS Zone Editor — manage records per domain.

The panel DB is the source of truth; on every change the whole zone is
re-synced to the DNS server via the provider. New domains are lazily seeded
with sensible default records the first time their zone is opened.
"""
from __future__ import annotations

import ipaddress
import re

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import RedirectResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import config
from ..db import get_db
from ..models import DnsRecord, Domain, User
from ..providers import get_provider
from ..security import current_user
from ..web import templates

router = APIRouter(prefix="/dns", tags=["dns"])

RECORD_TYPES = ["A", "AAAA", "CNAME", "MX", "TXT", "NS"]
_HOST_RE = re.compile(r"^(@|\*|[A-Za-z0-9_.-]{1,253})$")


def _flash(request: Request, message: str) -> None:
    request.session["flash"] = message


def _seed_defaults(db: Session, domain: Domain) -> None:
    """cPanel-style starter records for a brand-new zone."""
    ip = config.SERVER_IP
    defaults = [
        DnsRecord(domain_id=domain.id, rtype="A", name="@", value=ip),
        DnsRecord(domain_id=domain.id, rtype="A", name="www", value=ip),
        DnsRecord(domain_id=domain.id, rtype="MX", name="@", value=f"mail.{domain.name}.", priority=10),
        DnsRecord(domain_id=domain.id, rtype="TXT", name="@", value="v=spf1 a mx ~all"),
    ]
    db.add_all(defaults)
    db.commit()


def _sync(db: Session, domain: Domain) -> None:
    records = db.scalars(
        select(DnsRecord).where(DnsRecord.domain_id == domain.id).order_by(DnsRecord.id)
    ).all()
    payload = [
        {"type": r.rtype, "name": r.name, "value": r.value, "ttl": r.ttl, "priority": r.priority}
        for r in records
    ]
    get_provider().sync_zone(domain.name, payload)


@router.get("")
def zone_editor(
    request: Request,
    domain_id: int | None = None,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    domains = db.scalars(
        select(Domain).where(Domain.owner_id == user.id).order_by(Domain.name)
    ).all()
    flash = request.session.pop("flash", None)
    ctx = {"user": user, "domains": domains, "active": "dns", "flash": flash,
           "selected": None, "records": [], "types": RECORD_TYPES}

    if domains:
        selected = db.get(Domain, domain_id) if domain_id else domains[0]
        if selected is None or selected.owner_id != user.id:
            selected = domains[0]
        # Seed defaults on first visit, then sync the zone file.
        if not selected.dns_records:
            _seed_defaults(db, selected)
            _sync(db, selected)
        records = db.scalars(
            select(DnsRecord).where(DnsRecord.domain_id == selected.id).order_by(DnsRecord.rtype, DnsRecord.name)
        ).all()
        ctx.update({"selected": selected, "records": records})

    return templates.TemplateResponse(request, "dns.html", ctx)


@router.post("/{domain_id}/create")
def add_record(
    request: Request,
    domain_id: int,
    rtype: str = Form(...),
    name: str = Form("@"),
    value: str = Form(...),
    ttl: int = Form(14400),
    priority: int = Form(10),
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    domain = db.get(Domain, domain_id)
    if domain is None or domain.owner_id != user.id:
        _flash(request, "❌ Domain not found.")
        return RedirectResponse("/dns", status_code=303)

    name = (name or "@").strip()
    value = value.strip()
    rtype = rtype.upper()
    if rtype not in RECORD_TYPES:
        _flash(request, "❌ Unsupported record type.")
        return RedirectResponse(f"/dns?domain_id={domain_id}", status_code=303)
    if not _HOST_RE.match(name):
        _flash(request, "❌ Invalid record name.")
        return RedirectResponse(f"/dns?domain_id={domain_id}", status_code=303)
    # Light per-type validation.
    if rtype == "A" and not _is_ip(value, 4):
        _flash(request, "❌ A record needs a valid IPv4 address.")
        return RedirectResponse(f"/dns?domain_id={domain_id}", status_code=303)
    if rtype == "AAAA" and not _is_ip(value, 6):
        _flash(request, "❌ AAAA record needs a valid IPv6 address.")
        return RedirectResponse(f"/dns?domain_id={domain_id}", status_code=303)

    db.add(DnsRecord(
        domain_id=domain.id, rtype=rtype, name=name, value=value,
        ttl=ttl, priority=priority if rtype == "MX" else None,
    ))
    db.commit()
    _sync(db, domain)
    _flash(request, f"✅ {rtype} record added.")
    return RedirectResponse(f"/dns?domain_id={domain_id}", status_code=303)


@router.post("/records/{record_id}/update")
def update_record(
    request: Request,
    record_id: int,
    rtype: str = Form(...),
    name: str = Form("@"),
    value: str = Form(...),
    ttl: int = Form(14400),
    priority: int = Form(10),
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    record = db.get(DnsRecord, record_id)
    if record is None or record.domain.owner_id != user.id:
        _flash(request, "❌ Record not found.")
        return RedirectResponse("/dns", status_code=303)

    name = (name or "@").strip()
    value = value.strip()
    rtype = rtype.upper()
    domain = record.domain
    if rtype not in RECORD_TYPES or not _HOST_RE.match(name):
        _flash(request, "❌ Invalid record.")
        return RedirectResponse(f"/dns?domain_id={domain.id}", status_code=303)
    if rtype == "A" and not _is_ip(value, 4):
        _flash(request, "❌ A record needs a valid IPv4 address.")
        return RedirectResponse(f"/dns?domain_id={domain.id}", status_code=303)
    if rtype == "AAAA" and not _is_ip(value, 6):
        _flash(request, "❌ AAAA record needs a valid IPv6 address.")
        return RedirectResponse(f"/dns?domain_id={domain.id}", status_code=303)

    record.rtype = rtype
    record.name = name
    record.value = value
    record.ttl = ttl
    record.priority = priority if rtype == "MX" else None
    db.commit()
    _sync(db, domain)
    _flash(request, f"✅ {rtype} record updated.")
    return RedirectResponse(f"/dns?domain_id={domain.id}", status_code=303)


@router.post("/records/{record_id}/delete")
def delete_record(
    request: Request,
    record_id: int,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    record = db.get(DnsRecord, record_id)
    if record is None or record.domain.owner_id != user.id:
        _flash(request, "❌ Record not found.")
        return RedirectResponse("/dns", status_code=303)
    domain = record.domain
    db.delete(record)
    db.commit()
    _sync(db, domain)
    _flash(request, "🗑️ Record deleted.")
    return RedirectResponse(f"/dns?domain_id={domain.id}", status_code=303)


def _is_ip(value: str, version: int) -> bool:
    try:
        return ipaddress.ip_address(value).version == version
    except ValueError:
        return False
