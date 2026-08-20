"""Spam Filters (Rspamd) — per-domain tag-only spam handling.

Mirrors Email Deliverability: a domain dropdown, `owner_id == user.id` gating,
PRG + `_flash`, and a `_sync` that materializes the domain's slice through the
provider after every save. v1 is deliberately *tag-only* — spam is never
rejected at SMTP, only headered and (optionally) subject-tagged — so legitimate
mail is never bounced.

The page also hosts an admin-only "Enable spam filtering" server card
(ModSecurity-style in-handler admin check): the provider installs Rspamd and
chains it as a second Postfix milter after OpenDKIM, leaving DKIM signing
untouched. Non-admins can still tune per-domain settings; they take effect once
an admin enables filtering for the host.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import RedirectResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import config
from ..db import get_db
from ..models import Domain, SpamSetting, User
from ..providers import get_provider
from ..security import current_user
from ..web import templates

router = APIRouter(prefix="/spamfilters", tags=["spamfilters"])


def _flash(request: Request, message: str) -> None:
    request.session["flash"] = message


def _parse_list(raw: str) -> list[str]:
    """Newline-separated textarea -> a de-duped list of lowercase entries."""
    seen: list[str] = []
    for line in (raw or "").splitlines():
        entry = line.strip().lower()
        if entry and entry not in seen:
            seen.append(entry)
    return seen


def _checked(value: str) -> bool:
    """A checkbox is on only for an affirmative value (unchecked -> field absent)."""
    return (value or "").strip().lower() in ("1", "on", "true", "yes")


def _settings_dict(row: SpamSetting | None) -> dict:
    """The provider payload for a domain — the row's values, or tag-only defaults."""
    if row is None:
        return {
            "enabled": True,
            "threshold": config.SPAM_THRESHOLD_DEFAULT,
            "rewrite_subject": True,
            "whitelist": [],
            "blacklist": [],
        }
    return {
        "enabled": row.enabled,
        "threshold": row.threshold,
        "rewrite_subject": row.rewrite_subject,
        "whitelist": row.whitelist or [],
        "blacklist": row.blacklist or [],
    }


def _sync(db: Session, domain: Domain) -> None:
    row = db.scalar(select(SpamSetting).where(SpamSetting.domain_id == domain.id))
    get_provider().sync_spam_settings(domain.name, _settings_dict(row))


@router.get("")
def spam_home(
    request: Request,
    domain_id: int | None = None,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    domains = db.scalars(
        select(Domain).where(Domain.owner_id == user.id).order_by(Domain.name)
    ).all()
    flash = request.session.pop("flash", None)
    status = get_provider().spam_status()

    ctx = {
        "user": user,
        "is_admin": user.role == "admin",
        "domains": domains,
        "active": "spamfilters",
        "flash": flash,
        "status": status,
        "selected": None,
        "setting": None,
        "threshold_min": config.SPAM_THRESHOLD_MIN,
        "threshold_max": config.SPAM_THRESHOLD_MAX,
        "threshold_default": config.SPAM_THRESHOLD_DEFAULT,
    }

    if domains:
        selected = db.get(Domain, domain_id) if domain_id else domains[0]
        if selected is None or selected.owner_id != user.id:
            selected = domains[0]
        row = db.scalar(select(SpamSetting).where(SpamSetting.domain_id == selected.id))
        ctx.update({"selected": selected, "setting": row})

    return templates.TemplateResponse(request, "spamfilters.html", ctx)


@router.post("/{domain_id}/save")
def save_settings(
    request: Request,
    domain_id: int,
    threshold: str = Form(""),
    enabled: str = Form(""),
    rewrite_subject: str = Form(""),
    whitelist: str = Form(""),
    blacklist: str = Form(""),
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    domain = db.get(Domain, domain_id)
    if domain is None or domain.owner_id != user.id:
        _flash(request, "❌ Domain not found.")
        return RedirectResponse("/spamfilters", status_code=303)

    # Clamp the threshold to [MIN, MAX] so a bad score never reaches the daemon.
    try:
        score = int(threshold)
    except (TypeError, ValueError):
        score = config.SPAM_THRESHOLD_DEFAULT
    score = max(config.SPAM_THRESHOLD_MIN, min(config.SPAM_THRESHOLD_MAX, score))

    row = db.scalar(select(SpamSetting).where(SpamSetting.domain_id == domain.id))
    if row is None:
        row = SpamSetting(domain_id=domain.id)
        db.add(row)
    row.enabled = _checked(enabled)
    row.threshold = score
    row.rewrite_subject = _checked(rewrite_subject)
    row.whitelist = _parse_list(whitelist)
    row.blacklist = _parse_list(blacklist)
    db.commit()

    _sync(db, domain)
    _flash(request, f"✅ Spam settings saved for {domain.name}.")
    return RedirectResponse(f"/spamfilters?domain_id={domain.id}", status_code=303)


@router.post("/server-toggle")
async def server_toggle(
    request: Request,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    if user.role != "admin":
        _flash(request, "❌ Only an admin can enable server-wide spam filtering.")
        return RedirectResponse("/spamfilters", status_code=303)
    form = await request.form()
    enabled = (form.get("enabled") or "").strip() == "1"
    ok, message = get_provider().set_spam_filter(enabled)
    _flash(request, ("✅ " if ok else "❌ ") + message)
    return RedirectResponse("/spamfilters", status_code=303)
