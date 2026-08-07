"""Email account management — create mailboxes per domain."""
from __future__ import annotations

import re

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import RedirectResponse
from sqlalchemy import func, select
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
    from ..config import SERVER_IP
    domains = db.scalars(
        select(Domain).where(Domain.owner_id == user.id).order_by(Domain.name)
    ).all()
    flash = request.session.pop("flash", None)

    # Used/Available counter (matches cPanel's "74 Available, 26 Used" display).
    owned_domain_ids = [d.id for d in domains]
    used_count = db.scalar(
        select(func.count()).select_from(EmailAccount).where(EmailAccount.domain_id.in_(owned_domain_ids))
    ) or 0
    available = max(0, user.eff_email - used_count) if not user.unlimited and user.eff_email > 0 else 999

    ctx = {"user": user, "domains": domains, "active": "email", "flash": flash,
           "selected": None, "accounts": [], "used_count": used_count, "available": available,
           "mail_host": f"mail.{domains[0].name}" if domains else f"mail.{SERVER_IP}"}

    if domains:
        selected = db.get(Domain, domain_id) if domain_id else domains[0]
        if selected is None or selected.owner_id != user.id:
            selected = domains[0]
        accounts = db.scalars(
            select(EmailAccount).where(EmailAccount.domain_id == selected.id).order_by(EmailAccount.local_part)
        ).all()

        # Enrich each account with disk usage (for the storage meter). Best-effort:
        # a missing mailbox or no mail stack → 0 bytes, meter shows empty.
        provider = get_provider()
        rows = []
        for acc in accounts:
            used_bytes = provider.mailbox_usage(acc.address)
            quota_bytes = acc.quota_mb * 1024 * 1024
            pct = int(100 * used_bytes / quota_bytes) if quota_bytes > 0 else 0
            rows.append({
                "account": acc,
                "used_bytes": used_bytes,
                "quota_mb": acc.quota_mb,
                "pct": min(pct, 100),
                "over": used_bytes > quota_bytes,
            })
        ctx.update({"selected": selected, "accounts": rows, "mail_host": f"mail.{selected.name}"})

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
    try:
        get_provider().create_mailbox(address, password, quota_mb)
    except Exception as exc:  # noqa: BLE001 — surface a friendly reason, not a 500
        msg = str(exc)
        if "doveadm" in msg or "No such file" in msg:
            msg = "Mail server isn't set up on this host yet."
        _flash(request, f"❌ Could not create mailbox: {msg}")
        return RedirectResponse(f"/email?domain_id={domain_id}", status_code=303)
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


@router.get("/{account_id}/connect")
def connect_devices(
    request: Request,
    account_id: int,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    """Mail-client manual settings for one mailbox (cPanel's Connect Devices).

    Shows the IMAP/POP3/SMTP host + ports a phone or Thunderbird uses. The
    values match what setup-mail.sh actually serves: SSL/TLS on 993/995/465
    and STARTTLS on 143/110/587, all authenticating with the full address.
    """
    account = db.get(EmailAccount, account_id)
    if account is None or account.domain.owner_id != user.id:
        _flash(request, "❌ Mailbox not found.")
        return RedirectResponse("/email", status_code=303)
    domain = account.domain.name
    ctx = {
        "user": user,
        "active": "email",
        "account": account,
        "address": account.address,
        "domain": domain,
        # cPanel advertises mail.<domain>; our MX/A seed points it at this host.
        "mail_host": f"mail.{domain}",
        "ssl": [
            ("Incoming — IMAP", f"mail.{domain}", 993, "SSL/TLS"),
            ("Incoming — POP3", f"mail.{domain}", 995, "SSL/TLS"),
            ("Outgoing — SMTP", f"mail.{domain}", 465, "SSL/TLS"),
        ],
        "starttls": [
            ("Incoming — IMAP", f"mail.{domain}", 143, "STARTTLS"),
            ("Incoming — POP3", f"mail.{domain}", 110, "STARTTLS"),
            ("Outgoing — SMTP", f"mail.{domain}", 587, "STARTTLS"),
        ],
    }
    return templates.TemplateResponse(request, "email_connect.html", ctx)


@router.get("/{account_id}/sso")
def webmail_sso(
    request: Request,
    account_id: int,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    """Check Email → open this mailbox in Roundcube already logged in.

    Signs a short-lived token naming the mailbox and redirects to Roundcube's
    panel_sso plugin (`/webmail/?_sso=<token>`), which verifies it and logs in
    via the Dovecot master user. If the mail stack isn't wired for SSO (no
    shared secret) we just send the user to the plain webmail login page, so
    the button always does something sensible.
    """
    from ..config import WEBMAIL_SSO_SECRET, WEBMAIL_URL
    from ..security import make_webmail_sso_token

    account = db.get(EmailAccount, account_id)
    if account is None or account.domain.owner_id != user.id:
        _flash(request, "❌ Mailbox not found.")
        return RedirectResponse("/email", status_code=303)

    base = (WEBMAIL_URL or "/webmail").rstrip("/")
    if not WEBMAIL_SSO_SECRET:
        # Mail stack present but SSO not configured — fall back to manual login.
        return RedirectResponse(base or "/email", status_code=303)

    token = make_webmail_sso_token(account.address, WEBMAIL_SSO_SECRET)
    return RedirectResponse(f"{base}/?_sso={token}", status_code=303)


# Friendly message when the mail stack isn't installed on the host yet.
def _mail_err(exc: Exception) -> str:
    msg = str(exc)
    if "doveadm" in msg or "No such file" in msg:
        return "Mail server isn't set up on this host yet."
    return msg


@router.post("/{account_id}/password")
def change_email_password(
    request: Request,
    account_id: int,
    password: str = Form(...),
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    account = db.get(EmailAccount, account_id)
    if account is None or account.domain.owner_id != user.id:
        _flash(request, "❌ Mailbox not found.")
        return RedirectResponse("/email", status_code=303)
    domain_id = account.domain_id
    if len(password) < 6:
        _flash(request, "❌ Password must be at least 6 characters.")
        return RedirectResponse(f"/email?domain_id={domain_id}", status_code=303)
    address = account.address
    try:
        get_provider().set_mailbox_password(address, password)
    except Exception as exc:  # noqa: BLE001 — surface a friendly reason, not a 500
        _flash(request, f"❌ Could not change password: {_mail_err(exc)}")
        return RedirectResponse(f"/email?domain_id={domain_id}", status_code=303)
    _flash(request, f"🔑 Password changed for {address}.")
    return RedirectResponse(f"/email?domain_id={domain_id}", status_code=303)


@router.post("/{account_id}/quota")
def change_email_quota(
    request: Request,
    account_id: int,
    quota_mb: int = Form(...),
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    account = db.get(EmailAccount, account_id)
    if account is None or account.domain.owner_id != user.id:
        _flash(request, "❌ Mailbox not found.")
        return RedirectResponse("/email", status_code=303)
    domain_id = account.domain_id
    address = account.address
    try:
        quota_mb = max(1, int(quota_mb))
    except (TypeError, ValueError):
        quota_mb = account.quota_mb
    try:
        get_provider().set_mailbox_quota(address, quota_mb)
    except Exception as exc:  # noqa: BLE001 — surface a friendly reason, not a 500
        _flash(request, f"❌ Could not update quota: {_mail_err(exc)}")
        return RedirectResponse(f"/email?domain_id={domain_id}", status_code=303)
    account.quota_mb = quota_mb
    db.commit()
    _flash(request, f"✅ Quota for {address} set to {quota_mb} MB.")
    return RedirectResponse(f"/email?domain_id={domain_id}", status_code=303)
