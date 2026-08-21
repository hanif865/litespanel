"""Email Filters — cPanel-style per-mailbox Sieve rules + server-wide spam->Junk.

Two surfaces on one page:

* **Per mailbox:** a user builds rules (condition -> action) that compile to the
  mailbox's Sieve script. The panel is the sole owner of that script, so this
  router and the Autoresponders router both funnel through `resync_mailbox_sieve`
  (a mailbox can have filter rules *and* a vacation reply in the same script).
* **Server-wide (admin):** a toggle that makes Rspamd-tagged spam file into Junk.

The router stays DB-aware but system-agnostic: it gathers the rules + vacation
payload and hands it to the provider's `sync_mail_filters` (mirrors spam settings).
"""
from __future__ import annotations

import re

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import RedirectResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..db import get_db
from ..models import Autoresponder, Domain, MailFilter, User
from ..providers import get_provider
from ..security import current_user
from ..web import templates

router = APIRouter(prefix="/mailfilters", tags=["mailfilters"])

_LOCAL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9._-]{0,62}[a-z0-9])?$")

# Vocabulary the create form offers (kept in the router so the template and the
# validation agree). Values must match app/providers/sieve.py.
_FIELDS = ["From", "To", "Cc", "Subject", "Any Header", "Body"]
_OPS = ["contains", "is", "matches", "begins_with", "ends_with", "exists", "not_contains"]
_ACTIONS = ["fileinto", "redirect", "discard", "keep", "seen", "stop"]

_OP_LABEL = {
    "contains": "contains", "is": "is", "matches": "matches",
    "begins_with": "begins with", "ends_with": "ends with",
    "exists": "exists", "not_contains": "does not contain",
}
_ACT_LABEL = {
    "fileinto": "Move to", "redirect": "Redirect to", "discard": "Discard",
    "keep": "Keep in Inbox", "seen": "Mark as read", "stop": "Stop",
}


def _flash(request: Request, message: str) -> None:
    request.session["flash"] = message


def resync_mailbox_sieve(db: Session, domain: Domain, local_part: str) -> None:
    """Recompile one mailbox's Sieve script from *all* its enabled filters + the
    autoresponder vacation block, then hand the payload to the provider.

    Shared by this router and the Autoresponders router — the panel owns the
    single active script, so every edit on either side goes through here. Reads
    committed DB state, so callers must `db.commit()` *before* calling this.
    """
    filters = db.scalars(
        select(MailFilter)
        .where(MailFilter.domain_id == domain.id, MailFilter.local_part == local_part,
               MailFilter.enabled.is_(True))
        .order_by(MailFilter.priority, MailFilter.id)
    ).all()
    rules: list[dict] = []
    for mf in filters:
        rule = dict(mf.rules or {})
        rule["name"] = mf.name          # the row's name column is the display source
        rules.append(rule)

    ar = db.scalar(select(Autoresponder).where(
        Autoresponder.domain_id == domain.id, Autoresponder.local_part == local_part
    ))
    vacation = None
    if ar is not None and ar.enabled:
        # Autoresponder has no `days` field -> compiler defaults to :days 1.
        vacation = {"enabled": True, "subject": ar.subject, "body": ar.body}

    address = f"{local_part}@{domain.name}"
    get_provider().sync_mail_filters(address, rules, vacation)


def _summarize(rules: dict | None) -> str:
    """Build a short human description of a filter for the table (defensive)."""
    if not isinstance(rules, dict):
        return "—"
    conds = rules.get("conditions") or []
    acts = rules.get("actions") or []
    join = " and " if (rules.get("match") or "all") == "all" else " or "

    def cond_str(c: dict) -> str:
        field = c.get("field") or ""
        if field == "Any Header":
            field = c.get("header") or "header"
        op = _OP_LABEL.get(c.get("op") or "contains", c.get("op") or "")
        val = c.get("value") or ""
        if (c.get("op") or "") == "exists":
            return f"{field} exists"
        return f"{field} {op} \"{val}\"".strip()

    def act_str(a: dict) -> str:
        kind = a.get("type") or ""
        label = _ACT_LABEL.get(kind, kind)
        val = (a.get("value") or "").strip()
        return f"{label} {val}".strip() if val else label

    cond_part = join.join(cond_str(c) for c in conds) if conds else "(any message)"
    act_part = ", ".join(act_str(a) for a in acts) if acts else "(no action)"
    return f"If {cond_part} → {act_part}"


@router.get("")
def list_mailfilters(
    request: Request,
    domain_id: int | None = None,
    mailbox: str | None = None,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    domains = db.scalars(select(Domain).where(Domain.owner_id == user.id).order_by(Domain.name)).all()
    flash = request.session.pop("flash", None)
    try:
        status = get_provider().mail_filter_status()
    except Exception:
        status = {"available": False, "sieve_installed": False, "junk_enabled": False, "engine": "—"}

    ctx = {
        "user": user, "domains": domains, "active": "mailfilters", "flash": flash,
        "selected": None, "rows": [], "mailboxes": [], "mailbox": mailbox,
        "status": status, "fields": _FIELDS, "ops": _OPS, "actions": _ACTIONS,
    }
    if domains:
        selected = db.get(Domain, domain_id) if domain_id else domains[0]
        if selected is None or selected.owner_id != user.id:
            selected = domains[0]
        filters = db.scalars(
            select(MailFilter).where(MailFilter.domain_id == selected.id)
            .order_by(MailFilter.local_part, MailFilter.priority, MailFilter.id)
        ).all()
        mailboxes = sorted({mf.local_part for mf in filters})
        if mailbox:
            filters = [mf for mf in filters if mf.local_part == mailbox]
        rows = [{"mf": mf, "summary": _summarize(mf.rules)} for mf in filters]
        ctx.update({"selected": selected, "rows": rows, "mailboxes": mailboxes})
    return templates.TemplateResponse(request, "mailfilters.html", ctx)


@router.post("/create")
def create_mailfilter(
    request: Request,
    domain_id: int = Form(...),
    local_part: str = Form(...),
    name: str = Form(...),
    match: str = Form("all"),
    cond_field: str = Form(...),
    cond_header: str = Form(""),
    cond_op: str = Form("contains"),
    cond_value: str = Form(""),
    act_type: str = Form(...),
    act_value: str = Form(""),
    stop: str = Form(""),
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    domain = db.get(Domain, domain_id)
    if domain is None or domain.owner_id != user.id:
        _flash(request, "❌ Domain not found.")
        return RedirectResponse("/mailfilters", status_code=303)

    back = f"/mailfilters?domain_id={domain_id}"
    local_part = local_part.strip().lower()
    name = name.strip()[:128]
    match = "any" if match == "any" else "all"
    cond_field = cond_field if cond_field in _FIELDS else "Subject"
    cond_op = cond_op if cond_op in _OPS else "contains"
    act_type = act_type if act_type in _ACTIONS else "fileinto"
    cond_header = cond_header.strip()[:64]
    cond_value = cond_value.strip()[:255]
    act_value = act_value.strip()[:255]

    if not _LOCAL_RE.match(local_part):
        _flash(request, "❌ Invalid mailbox name.")
        return RedirectResponse(back, status_code=303)
    if not name:
        _flash(request, "❌ A filter name is required.")
        return RedirectResponse(back, status_code=303)
    if cond_field == "Any Header" and not cond_header:
        _flash(request, "❌ Enter the header name to match.")
        return RedirectResponse(back, status_code=303)
    if cond_op != "exists" and not cond_value:
        _flash(request, "❌ Enter the text to match.")
        return RedirectResponse(back, status_code=303)
    if act_type in ("fileinto", "redirect") and not act_value:
        label = "folder" if act_type == "fileinto" else "destination address"
        _flash(request, f"❌ Enter the {label} for the action.")
        return RedirectResponse(back, status_code=303)
    if db.scalar(select(MailFilter).where(
        MailFilter.domain_id == domain.id, MailFilter.local_part == local_part,
        MailFilter.name == name,
    )):
        _flash(request, f"❌ A filter named “{name}” already exists for {local_part}@{domain.name}.")
        return RedirectResponse(back, status_code=303)

    conditions = [{"field": cond_field, "op": cond_op, "value": cond_value, "header": cond_header}]
    actions = [{"type": act_type, "value": act_value}]
    if stop and act_type != "stop":
        actions.append({"type": "stop"})
    rules = {"match": match, "conditions": conditions, "actions": actions}

    mf = MailFilter(domain_id=domain.id, local_part=local_part, name=name, rules=rules, enabled=True)
    db.add(mf)
    db.commit()
    resync_mailbox_sieve(db, domain, local_part)
    _flash(request, f"✅ Filter “{name}” created for {local_part}@{domain.name}.")
    return RedirectResponse(f"{back}&mailbox={local_part}", status_code=303)


@router.post("/junk/toggle")
def toggle_junk_delivery(
    request: Request,
    enabled: str = Form(""),
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    # Server-wide: admin only (like the Spam Filters server toggle). Declared
    # before the "/{mf_id}/..." routes so "junk" isn't parsed as an id (-> 422).
    if user.role != "admin":
        _flash(request, "❌ Only an administrator can change server-wide spam delivery.")
        return RedirectResponse("/mailfilters", status_code=303)
    want = enabled == "on"
    ok, message = get_provider().set_junk_delivery(want)
    _flash(request, ("✅ " if ok else "❌ ") + message)
    return RedirectResponse("/mailfilters", status_code=303)


@router.post("/{mf_id}/toggle")
def toggle_mailfilter(
    request: Request,
    mf_id: int,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    mf = db.get(MailFilter, mf_id)
    if mf is None or mf.domain.owner_id != user.id:
        _flash(request, "❌ Not found.")
        return RedirectResponse("/mailfilters", status_code=303)
    domain, local_part = mf.domain, mf.local_part
    mf.enabled = not mf.enabled
    db.commit()
    resync_mailbox_sieve(db, domain, local_part)
    _flash(request, f"{'▶️ Enabled' if mf.enabled else '⏸️ Disabled'} filter “{mf.name}”.")
    return RedirectResponse(f"/mailfilters?domain_id={mf.domain_id}&mailbox={local_part}", status_code=303)


@router.post("/{mf_id}/delete")
def delete_mailfilter(
    request: Request,
    mf_id: int,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    mf = db.get(MailFilter, mf_id)
    if mf is None or mf.domain.owner_id != user.id:
        _flash(request, "❌ Not found.")
        return RedirectResponse("/mailfilters", status_code=303)
    domain, local_part, dom_id, fname = mf.domain, mf.local_part, mf.domain_id, mf.name
    db.delete(mf)
    db.commit()
    resync_mailbox_sieve(db, domain, local_part)
    _flash(request, f"🗑️ Filter “{fname}” removed.")
    return RedirectResponse(f"/mailfilters?domain_id={dom_id}&mailbox={local_part}", status_code=303)
