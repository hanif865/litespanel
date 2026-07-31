"""Web Disk — WebDAV logins giving file access over HTTP(S).

Mirrors the FTP feature: the panel DB is source of truth, the provider
materializes the real WebDAV credential (an htpasswd entry + nginx dav location
on linux, a passwd file in the demo). Passwords are encrypted at rest only so
the login can be re-materialized; the plaintext is shown to the user once.
"""
from __future__ import annotations

import re
import secrets
from pathlib import PurePosixPath

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import RedirectResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import crypto
from ..db import get_db
from ..models import Domain, User, WebDiskAccount
from ..providers import get_provider
from ..security import current_user
from ..web import templates

router = APIRouter(prefix="/webdisk", tags=["webdisk"])

# Web Disk login local part: a plain slug. Full login is "<local>@<domain>".
_LOCAL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9._-]{0,30}[a-z0-9])?$")


def _flash(request: Request, message: str) -> None:
    request.session["flash"] = message


def _safe_subdir(docroot: str, subdir: str) -> str | None:
    """Resolve an optional subdirectory under docroot, rejecting traversal."""
    subdir = (subdir or "").strip().strip("/")
    if not subdir:
        return docroot
    parts = PurePosixPath(subdir.replace("\\", "/")).parts
    if any(p in ("..", "") or ":" in p for p in parts):
        return None
    return str(PurePosixPath(docroot) / PurePosixPath(*parts))


@router.get("")
def list_webdisk(request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)):
    accounts = db.scalars(
        select(WebDiskAccount).where(WebDiskAccount.owner_id == user.id).order_by(WebDiskAccount.username)
    ).all()
    domains = db.scalars(
        select(Domain).where(Domain.owner_id == user.id).order_by(Domain.name)
    ).all()
    flash = request.session.pop("flash", None)
    new_cred = request.session.pop("new_webdisk_cred", None)
    return templates.TemplateResponse(
        request,
        "webdisk.html",
        {"user": user, "accounts": accounts, "domains": domains,
         "active": "webdisk", "flash": flash, "new_cred": new_cred},
    )


@router.post("/create")
def create_webdisk(
    request: Request,
    local_part: str = Form(...),
    domain_id: int = Form(...),
    directory: str = Form(""),
    read_only: str = Form(""),
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    domain = db.get(Domain, domain_id)
    if domain is None or domain.owner_id != user.id:
        _flash(request, "❌ Domain not found.")
        return RedirectResponse("/webdisk", status_code=303)

    local_part = local_part.strip().lower()
    if not _LOCAL_RE.match(local_part):
        _flash(request, "❌ Invalid username (letters, digits, dot, dash, underscore).")
        return RedirectResponse("/webdisk", status_code=303)

    username = f"{local_part}@{domain.name}"
    if db.scalar(select(WebDiskAccount).where(WebDiskAccount.username == username)):
        _flash(request, f"❌ Web Disk account '{username}' already exists.")
        return RedirectResponse("/webdisk", status_code=303)

    home_dir = _safe_subdir(domain.docroot, directory)
    if home_dir is None:
        _flash(request, "❌ Directory must be a relative path inside the site (no '..').")
        return RedirectResponse("/webdisk", status_code=303)

    ro = read_only == "on"
    password = secrets.token_urlsafe(12)
    get_provider().create_webdisk_account(username, password, home_dir, ro)
    db.add(WebDiskAccount(owner_id=user.id, username=username,
                          password_enc=crypto.encrypt(password),
                          home_dir=home_dir, read_only=ro))
    db.commit()
    request.session["new_webdisk_cred"] = {"username": username, "password": password,
                                           "home_dir": home_dir}
    _flash(request, f"✅ Web Disk account '{username}' created.")
    return RedirectResponse("/webdisk", status_code=303)


@router.post("/{acct_id}/password")
def reset_webdisk_password(
    request: Request,
    acct_id: int,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    acct = db.get(WebDiskAccount, acct_id)
    if acct is None or acct.owner_id != user.id:
        _flash(request, "❌ Web Disk account not found.")
        return RedirectResponse("/webdisk", status_code=303)
    password = secrets.token_urlsafe(12)
    get_provider().set_webdisk_password(acct.username, password)
    acct.password_enc = crypto.encrypt(password)
    db.commit()
    request.session["new_webdisk_cred"] = {"username": acct.username, "password": password,
                                           "home_dir": acct.home_dir}
    _flash(request, f"🔑 Password reset for '{acct.username}'.")
    return RedirectResponse("/webdisk", status_code=303)


@router.post("/{acct_id}/delete")
def delete_webdisk(
    request: Request,
    acct_id: int,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    acct = db.get(WebDiskAccount, acct_id)
    if acct is None or acct.owner_id != user.id:
        _flash(request, "❌ Web Disk account not found.")
        return RedirectResponse("/webdisk", status_code=303)
    get_provider().delete_webdisk_account(acct.username)
    username = acct.username
    db.delete(acct)
    db.commit()
    _flash(request, f"🗑️ Web Disk account '{username}' removed.")
    return RedirectResponse("/webdisk", status_code=303)
