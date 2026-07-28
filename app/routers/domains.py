"""Domain / website hosting management."""
from __future__ import annotations

import re
import shutil
from pathlib import Path

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import RedirectResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..accounts import account_home
from ..db import get_db
from ..models import Domain, User
from ..limits import domain_limit_reached
from ..providers import get_provider
from ..security import current_user
from ..web import templates

router = APIRouter(prefix="/domains", tags=["domains"])

# Basic hostname validation — labels of letters/digits/hyphens, dot-separated.
_DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63})+$")


def _flash(request: Request, message: str) -> None:
    request.session["flash"] = message


@router.get("")
def list_domains(request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)):
    domains = db.scalars(
        select(Domain).where(Domain.owner_id == user.id).order_by(Domain.name)
    ).all()
    flash = request.session.pop("flash", None)
    return templates.TemplateResponse(
        request, "domains.html", {"user": user, "domains": domains, "active": "domains", "flash": flash}
    )


@router.post("/create")
def create_domain(
    request: Request,
    name: str = Form(...),
    php_version: str = Form("8.3"),
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    if domain_limit_reached(db, user):
        _flash(request, f"❌ Domain limit reached ({user.max_domains}). Contact your provider.")
        return RedirectResponse("/domains", status_code=303)
    name = name.strip().lower().removeprefix("www.")
    if not _DOMAIN_RE.match(name):
        _flash(request, f"❌ '{name}' is not a valid domain name.")
        return RedirectResponse("/domains", status_code=303)
    if db.scalar(select(Domain).where(Domain.name == name)):
        _flash(request, f"❌ {name} already exists.")
        return RedirectResponse("/domains", status_code=303)

    # Provision (or reuse) the owner's isolated system account, then place the
    # site under its home so PHP runs as that account.
    home = account_home(db, user)
    docroot = home / name / "public_html"
    get_provider().create_site(name, docroot, php_version, user.system_user)
    get_provider().reload_web()
    db.add(Domain(name=name, owner_id=user.id, docroot=str(docroot), php_version=php_version))
    db.commit()
    _flash(request, f"✅ {name} created and is now live.")
    return RedirectResponse("/domains", status_code=303)


@router.post("/{domain_id}/delete")
def delete_domain(
    request: Request,
    domain_id: int,
    remove_files: str = Form(""),
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    domain = db.get(Domain, domain_id)
    if domain is None or domain.owner_id != user.id:
        _flash(request, "❌ Domain not found.")
        return RedirectResponse("/domains", status_code=303)

    get_provider().remove_site(domain.name)
    get_provider().reload_web()
    # Only wipe files if the user explicitly opted in.
    if remove_files == "on":
        site_dir = __import__("pathlib").Path(domain.docroot).parent
        shutil.rmtree(site_dir, ignore_errors=True)
    name = domain.name
    db.delete(domain)
    db.commit()
    _flash(request, f"🗑️ {name} removed.")
    return RedirectResponse("/domains", status_code=303)
