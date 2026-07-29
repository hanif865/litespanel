"""SSL certificate management (Let's Encrypt)."""
from __future__ import annotations

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import RedirectResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..db import get_db
from ..models import Certificate, Domain, User
from ..providers import get_provider
from ..security import current_user
from ..web import templates

router = APIRouter(prefix="/ssl", tags=["ssl"])


def _flash(request: Request, message: str) -> None:
    request.session["flash"] = message


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

    info = get_provider().issue_certificate(domain.name)
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
