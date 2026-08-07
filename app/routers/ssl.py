"""SSL certificate management (Let's Encrypt)."""
from __future__ import annotations

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import RedirectResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..db import get_db
from ..models import Certificate, Domain, Subdomain, User
from ..providers import get_provider
from ..security import current_user
from ..web import templates

router = APIRouter(prefix="/ssl", tags=["ssl"])


def _flash(request: Request, message: str) -> None:
    request.session["flash"] = message


def _ssl_error_reason(exc: Exception) -> str:
    """Condense a certificate-issue failure into one short, actionable line.

    The linux provider raises RuntimeError("<certbot cmd> failed: <stderr>"); the
    part after "failed:" is certbot's own diagnostic (DNS not pointing here, port
    80 unreachable, Let's Encrypt rate limit) and is what the operator needs — so
    surface that, collapsed to a single trimmed line, instead of 500-ing the route
    or dumping the whole certbot command line into the flash.
    """
    text = str(exc).strip()
    _, sep, tail = text.partition("failed:")
    reason = (tail if sep else text).strip()
    reason = " ".join(reason.split())          # collapse newlines/indentation
    return reason[:300] or "certificate issuance failed"


@router.get("")
def list_ssl(request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)):
    domains = db.scalars(
        select(Domain).where(Domain.owner_id == user.id).order_by(Domain.name)
    ).all()
    flash = request.session.pop("flash", None)
    return templates.TemplateResponse(
        request, "ssl.html", {"user": user, "domains": domains, "active": "ssl", "flash": flash}
    )


@router.post("/{domain_id}/issue")
def issue(
    request: Request,
    domain_id: int,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    domain = db.get(Domain, domain_id)
    if domain is None or domain.owner_id != user.id:
        _flash(request, "❌ Domain not found.")
        return RedirectResponse("/ssl", status_code=303)

    try:
        info = get_provider().issue_certificate(domain.name)
    except Exception as exc:  # noqa: BLE001 — certbot failed; show why, don't 500.
        _flash(request, f"❌ SSL for {domain.name} failed: {_ssl_error_reason(exc)}")
        return RedirectResponse("/ssl", status_code=303)
    # Replace any existing cert record for this domain.
    existing = db.scalar(select(Certificate).where(Certificate.domain_id == domain.id))
    if existing:
        db.delete(existing)
        db.flush()
    db.add(Certificate(
        domain_id=domain.id, issuer=info.issuer,
        issued_at=info.issued_at, expires_at=info.expires_at, cert_path=info.cert_path,
    ))
    # Force HTTPS now that there's a cert, so http:// redirects to https://
    # (green padlock, no more "Not secure") — cPanel-style AutoSSL behaviour.
    domain.force_https = True
    try:
        get_provider().set_https_redirect(
            domain.name, domain.docroot, domain.php_version,
            domain.owner.system_user or domain.owner.username, True, True)
    except Exception:  # noqa: BLE001 — cert is recorded even if the rewrite hiccups
        pass
    db.commit()
    _flash(request, f"🔒 SSL issued for {domain.name} (expires {info.expires_at:%Y-%m-%d}); HTTPS is now forced.")
    return RedirectResponse("/ssl", status_code=303)


@router.post("/{domain_id}/revoke")
def revoke(
    request: Request,
    domain_id: int,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    domain = db.get(Domain, domain_id)
    if domain is None or domain.owner_id != user.id:
        _flash(request, "❌ Domain not found.")
        return RedirectResponse("/ssl", status_code=303)
    get_provider().revoke_certificate(domain.name)
    if domain.certificate:
        db.delete(domain.certificate)
        db.commit()
    _flash(request, f"🔓 SSL revoked for {domain.name}.")
    return RedirectResponse("/ssl", status_code=303)


# --- Subdomains ----------------------------------------------------------
# Subdomains live in their own table and own their own vhost, so they get
# their own routes. Ownership runs through the parent domain. No force-HTTPS
# rewrite here: certbot's --nginx --redirect already patches the subdomain's
# own <fqdn>.conf, and set_https_redirect() hardcodes the parent's server_name.


@router.post("/sub/{sub_id}/issue")
def issue_sub(
    request: Request,
    sub_id: int,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    sub = db.get(Subdomain, sub_id)
    if sub is None or sub.parent.owner_id != user.id:
        _flash(request, "❌ Subdomain not found.")
        return RedirectResponse("/ssl", status_code=303)

    try:
        info = get_provider().issue_certificate(sub.fqdn)
    except Exception as exc:  # noqa: BLE001 — certbot failed; show why, don't 500.
        _flash(request, f"❌ SSL for {sub.fqdn} failed: {_ssl_error_reason(exc)}")
        return RedirectResponse("/ssl", status_code=303)
    # Replace any existing cert record for this subdomain.
    existing = db.scalar(select(Certificate).where(Certificate.subdomain_id == sub.id))
    if existing:
        db.delete(existing)
        db.flush()
    db.add(Certificate(
        subdomain_id=sub.id, domain_id=None, issuer=info.issuer,
        issued_at=info.issued_at, expires_at=info.expires_at, cert_path=info.cert_path,
    ))
    db.commit()
    _flash(request, f"🔒 SSL issued for {sub.fqdn} (expires {info.expires_at:%Y-%m-%d}).")
    return RedirectResponse("/ssl", status_code=303)


@router.post("/sub/{sub_id}/revoke")
def revoke_sub(
    request: Request,
    sub_id: int,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    sub = db.get(Subdomain, sub_id)
    if sub is None or sub.parent.owner_id != user.id:
        _flash(request, "❌ Subdomain not found.")
        return RedirectResponse("/ssl", status_code=303)
    get_provider().revoke_certificate(sub.fqdn)
    if sub.certificate:
        db.delete(sub.certificate)
        db.commit()
    _flash(request, f"🔓 SSL revoked for {sub.fqdn}.")
    return RedirectResponse("/ssl", status_code=303)
