"""PHP version selector — set the PHP-FPM version per domain."""
from __future__ import annotations

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import RedirectResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..db import get_db
from ..models import Domain, User
from ..providers import get_provider
from ..security import current_user
from ..web import templates

router = APIRouter(prefix="/php", tags=["php"])

PHP_VERSIONS = ["8.3", "8.2", "8.1", "8.0", "7.4"]


def _flash(request: Request, message: str) -> None:
    request.session["flash"] = message


@router.get("")
def php_versions(request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)):
    domains = db.scalars(
        select(Domain).where(Domain.owner_id == user.id).order_by(Domain.name)
    ).all()
    flash = request.session.pop("flash", None)
    return templates.TemplateResponse(
        request,
        "php.html",
        {"user": user, "domains": domains, "versions": PHP_VERSIONS, "active": "php", "flash": flash},
    )


@router.post("/{domain_id}/set")
def set_version(
    request: Request,
    domain_id: int,
    php_version: str = Form(...),
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    domain = db.get(Domain, domain_id)
    if domain is None or domain.owner_id != user.id:
        _flash(request, "❌ Domain not found.")
        return RedirectResponse("/php", status_code=303)
    if php_version not in PHP_VERSIONS:
        _flash(request, "❌ Unsupported PHP version.")
        return RedirectResponse("/php", status_code=303)

    get_provider().set_php_version(
        domain.name, domain.docroot, php_version, domain.owner.system_user or domain.owner.username
    )
    get_provider().reload_web()
    domain.php_version = php_version
    db.commit()
    _flash(request, f"✅ {domain.name} now runs PHP {php_version}.")
    return RedirectResponse("/php", status_code=303)
