"""User Manager — WHM-style multi-user / reseller administration.

- Admins see and manage every account and may create resellers or users.
- Resellers see and manage only the accounts they created (always role "user").
- Regular users cannot reach this section (guarded by require_manager).
"""
from __future__ import annotations

import re
import shutil
from pathlib import Path

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import RedirectResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import config
from ..db import get_db
from ..models import CronJob, Database, Domain, Package, User
from ..providers import get_provider
from ..routers.packages import visible_packages
from ..security import current_user, hash_password, require_manager
from ..web import templates

router = APIRouter(prefix="/users", tags=["users"])

_USERNAME_RE = re.compile(r"^[a-z][a-z0-9_]{2,31}$")


def _flash(request: Request, message: str) -> None:
    request.session["flash"] = message


def _visible_users(db: Session, manager: User) -> list[User]:
    stmt = select(User).order_by(User.username)
    if manager.role == "reseller":
        stmt = stmt.where(User.created_by_id == manager.id)
    return list(db.scalars(stmt))


def _can_manage(manager: User, target: User) -> bool:
    if target.id == manager.id:
        return False                      # never act on yourself here
    if manager.role == "admin":
        return True
    return target.created_by_id == manager.id and manager.role == "reseller"


def _owned_package(db: Session, manager: User, package_id: int | None) -> Package | None:
    """Resolve a package the manager is allowed to assign, or None."""
    if not package_id:
        return None
    pkg = db.get(Package, package_id)
    if pkg is None or (manager.role != "admin" and pkg.owner_id != manager.id):
        return None
    return pkg


@router.get("")
def list_users(request: Request, manager: User = Depends(require_manager), db: Session = Depends(get_db)):
    users = _visible_users(db, manager)
    packages = visible_packages(db, manager)
    flash = request.session.pop("flash", None)
    return templates.TemplateResponse(
        request,
        "users.html",
        {"user": manager, "users": users, "packages": packages, "active": "users", "flash": flash},
    )


@router.post("/create")
def create_user(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    role: str = Form("user"),
    package_id: int = Form(0),
    max_domains: int = Form(0),
    max_databases: int = Form(0),
    max_email: int = Form(0),
    disk_quota_mb: int = Form(0),
    manager: User = Depends(require_manager),
    db: Session = Depends(get_db),
):
    username = username.strip().lower()
    if not _USERNAME_RE.match(username):
        _flash(request, "❌ Username: 3–32 chars, start with a letter, [a-z0-9_].")
        return RedirectResponse("/users", status_code=303)
    if len(password) < 6:
        _flash(request, "❌ Password must be at least 6 characters.")
        return RedirectResponse("/users", status_code=303)
    if db.scalar(select(User).where(User.username == username)):
        _flash(request, f"❌ User '{username}' already exists.")
        return RedirectResponse("/users", status_code=303)

    # Resellers may only create plain users; admins may also create resellers.
    if manager.role != "admin" or role not in ("user", "reseller"):
        role = "user"

    pkg = _owned_package(db, manager, package_id)
    new_user = User(
        username=username, password_hash=hash_password(password),
        role=role, is_admin=(role == "admin"), created_by_id=manager.id,
        package_id=pkg.id if pkg else None,
        # Inline limits still stored as a fallback / for accounts with no package.
        max_domains=max(0, max_domains), max_databases=max(0, max_databases),
        max_email=max(0, max_email), disk_quota_mb=max(0, disk_quota_mb),
    )
    db.add(new_user)
    db.commit()

    # Hosting accounts get an isolated system user (their own /home + PHP pool).
    if role == "user":
        new_user.system_user = username
        db.commit()
        get_provider().ensure_account(username)

    plan = f" on package '{pkg.name}'" if pkg else ""
    _flash(request, f"✅ {role.capitalize()} '{username}' created{plan}.")
    return RedirectResponse("/users", status_code=303)


@router.post("/{user_id}/package")
def change_package(
    request: Request,
    user_id: int,
    package_id: int = Form(0),
    manager: User = Depends(require_manager),
    db: Session = Depends(get_db),
):
    target = db.get(User, user_id)
    if target is None or not _can_manage(manager, target):
        _flash(request, "❌ Not allowed.")
        return RedirectResponse("/users", status_code=303)
    pkg = _owned_package(db, manager, package_id)
    target.package_id = pkg.id if pkg else None
    db.commit()
    _flash(request, f"✅ {target.username} → {pkg.name if pkg else 'custom limits'}.")
    return RedirectResponse("/users", status_code=303)


@router.post("/{user_id}/suspend")
def suspend_user(
    request: Request, user_id: int,
    manager: User = Depends(require_manager), db: Session = Depends(get_db),
):
    return _set_suspended(request, user_id, True, manager, db)


@router.post("/{user_id}/unsuspend")
def unsuspend_user(
    request: Request, user_id: int,
    manager: User = Depends(require_manager), db: Session = Depends(get_db),
):
    return _set_suspended(request, user_id, False, manager, db)


def _set_suspended(request, user_id, value, manager, db):
    target = db.get(User, user_id)
    if target is None or not _can_manage(manager, target):
        _flash(request, "❌ Not allowed.")
        return RedirectResponse("/users", status_code=303)
    target.suspended = value
    db.commit()
    _flash(request, f"{'⏸️ Suspended' if value else '▶️ Reactivated'} {target.username}.")
    return RedirectResponse("/users", status_code=303)


@router.post("/{user_id}/delete")
def delete_user(
    request: Request, user_id: int,
    manager: User = Depends(require_manager), db: Session = Depends(get_db),
):
    target = db.get(User, user_id)
    if target is None or not _can_manage(manager, target):
        _flash(request, "❌ Not allowed.")
        return RedirectResponse("/users", status_code=303)

    provider = get_provider()
    # Tear down the target's system artifacts before removing DB rows.
    for domain in list(target.domains):
        for sub in list(domain.subdomains):
            provider.remove_subdomain(sub.fqdn)
        provider.remove_site(domain.name)
    for database in list(target.databases):
        provider.drop_database(database.name, database.db_user)
    for backup in list(target.backups):
        (config.BACKUPS_DIR / backup.filename).unlink(missing_ok=True)
    # Remove the whole isolated account (system user, /home, PHP-FPM pool).
    if target.system_user:
        provider.remove_account(target.system_user)
    else:
        for domain in list(target.domains):
            shutil.rmtree(Path(domain.docroot).parent, ignore_errors=True)

    username = target.username
    db.delete(target)          # cascades domains/databases/cron/backups + nested rows
    db.commit()
    provider.reload_web()
    # Re-sync the crontab now that this user's jobs are gone.
    remaining = db.scalars(select(CronJob).order_by(CronJob.id)).all()
    provider.sync_cron([f"{j.schedule} {j.command}" for j in remaining])
    _flash(request, f"🗑️ Account '{username}' and all its resources removed.")
    return RedirectResponse("/users", status_code=303)
