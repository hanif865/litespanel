"""Packages — reusable hosting plans (WHM-style).

A package bundles account limits under a name. Assign it to users (in the User
Manager) instead of typing limits each time; editing the package updates every
account on it. Admins manage all packages; resellers manage their own.
"""
from __future__ import annotations

import re

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import RedirectResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..db import get_db
from ..models import Package, User
from ..security import require_manager
from ..web import templates

router = APIRouter(prefix="/packages", tags=["packages"])

_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 _-]{1,63}$")


def _flash(request: Request, message: str) -> None:
    request.session["flash"] = message


def visible_packages(db: Session, manager: User) -> list[Package]:
    stmt = select(Package).order_by(Package.name)
    if manager.role == "reseller":
        stmt = stmt.where(Package.owner_id == manager.id)
    return list(db.scalars(stmt))


@router.get("")
def list_packages(request: Request, manager: User = Depends(require_manager), db: Session = Depends(get_db)):
    packages = visible_packages(db, manager)
    flash = request.session.pop("flash", None)
    return templates.TemplateResponse(
        request, "packages.html", {"user": manager, "packages": packages, "active": "packages", "flash": flash}
    )


@router.post("/create")
def create_package(
    request: Request,
    name: str = Form(...),
    max_domains: int = Form(0),
    max_databases: int = Form(0),
    max_email: int = Form(0),
    disk_quota_mb: int = Form(0),
    manager: User = Depends(require_manager),
    db: Session = Depends(get_db),
):
    name = name.strip()
    if not _NAME_RE.match(name):
        _flash(request, "❌ Invalid package name.")
        return RedirectResponse("/packages", status_code=303)
    if db.scalar(select(Package).where(Package.owner_id == manager.id, Package.name == name)):
        _flash(request, f"❌ Package '{name}' already exists.")
        return RedirectResponse("/packages", status_code=303)

    db.add(Package(
        name=name, owner_id=manager.id,
        max_domains=max(0, max_domains), max_databases=max(0, max_databases),
        max_email=max(0, max_email), disk_quota_mb=max(0, disk_quota_mb),
    ))
    db.commit()
    _flash(request, f"✅ Package '{name}' created.")
    return RedirectResponse("/packages", status_code=303)


@router.post("/{package_id}/update")
def update_package(
    request: Request,
    package_id: int,
    max_domains: int = Form(0),
    max_databases: int = Form(0),
    max_email: int = Form(0),
    disk_quota_mb: int = Form(0),
    manager: User = Depends(require_manager),
    db: Session = Depends(get_db),
):
    pkg = db.get(Package, package_id)
    if pkg is None or (manager.role != "admin" and pkg.owner_id != manager.id):
        _flash(request, "❌ Not allowed.")
        return RedirectResponse("/packages", status_code=303)
    pkg.max_domains = max(0, max_domains)
    pkg.max_databases = max(0, max_databases)
    pkg.max_email = max(0, max_email)
    pkg.disk_quota_mb = max(0, disk_quota_mb)
    db.commit()
    _flash(request, f"✅ Package '{pkg.name}' updated — all its accounts now use the new limits.")
    return RedirectResponse("/packages", status_code=303)


@router.post("/{package_id}/delete")
def delete_package(
    request: Request,
    package_id: int,
    manager: User = Depends(require_manager),
    db: Session = Depends(get_db),
):
    pkg = db.get(Package, package_id)
    if pkg is None or (manager.role != "admin" and pkg.owner_id != manager.id):
        _flash(request, "❌ Not allowed.")
        return RedirectResponse("/packages", status_code=303)
    if pkg.users:
        _flash(request, f"❌ '{pkg.name}' is assigned to {len(pkg.users)} account(s). Reassign them first.")
        return RedirectResponse("/packages", status_code=303)
    name = pkg.name
    db.delete(pkg)
    db.commit()
    _flash(request, f"🗑️ Package '{name}' deleted.")
    return RedirectResponse("/packages", status_code=303)
