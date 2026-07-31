"""FTP accounts — virtual FTP/SFTP logins jailed to a directory.

The panel DB is the source of truth; the provider materializes the real login
(pure-ftpd virtual user on linux, a passwd file in the demo). Passwords are
stored encrypted at rest only so the login can be re-materialized on the host —
they're shown to the user once at creation and never again.
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
from ..models import Domain, FtpAccount, User
from ..providers import get_provider
from ..security import current_user
from ..web import templates

router = APIRouter(prefix="/ftp", tags=["ftp"])

# FTP login local part: a plain slug. The full login is "<local>@<domain>".
_LOCAL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9._-]{0,30}[a-z0-9])?$")


def _flash(request: Request, message: str) -> None:
    request.session["flash"] = message


def _safe_subdir(docroot: str, subdir: str) -> str | None:
    """Resolve an optional subdirectory under docroot, rejecting traversal."""
    subdir = (subdir or "").strip().strip("/")
    if not subdir:
        return docroot
    # No absolute paths, no "..", no drive letters — a relative path only.
    parts = PurePosixPath(subdir.replace("\\", "/")).parts
    if any(p in ("..", "") or ":" in p for p in parts):
        return None
    return str(PurePosixPath(docroot) / PurePosixPath(*parts))


@router.get("")
def list_ftp(request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)):
    accounts = db.scalars(
        select(FtpAccount).where(FtpAccount.owner_id == user.id).order_by(FtpAccount.username)
    ).all()
    domains = db.scalars(
        select(Domain).where(Domain.owner_id == user.id).order_by(Domain.name)
    ).all()
    flash = request.session.pop("flash", None)
    # A freshly generated password shown once after creation.
    new_cred = request.session.pop("new_ftp_cred", None)
    return templates.TemplateResponse(
        request,
        "ftp.html",
        {"user": user, "accounts": accounts, "domains": domains,
         "active": "ftp", "flash": flash, "new_cred": new_cred},
    )


@router.post("/create")
def create_ftp(
    request: Request,
    local_part: str = Form(...),
    domain_id: int = Form(...),
    directory: str = Form(""),
    quota_mb: int = Form(0),
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    domain = db.get(Domain, domain_id)
    if domain is None or domain.owner_id != user.id:
        _flash(request, "❌ Domain not found.")
        return RedirectResponse("/ftp", status_code=303)

    local_part = local_part.strip().lower()
    if not _LOCAL_RE.match(local_part):
        _flash(request, "❌ Invalid username (letters, digits, dot, dash, underscore).")
        return RedirectResponse("/ftp", status_code=303)

    username = f"{local_part}@{domain.name}"
    if db.scalar(select(FtpAccount).where(FtpAccount.username == username)):
        _flash(request, f"❌ FTP account '{username}' already exists.")
        return RedirectResponse("/ftp", status_code=303)

    home_dir = _safe_subdir(domain.docroot, directory)
    if home_dir is None:
        _flash(request, "❌ Directory must be a relative path inside the site (no '..').")
        return RedirectResponse("/ftp", status_code=303)

    try:
        quota_mb = max(0, int(quota_mb))
    except (TypeError, ValueError):
        quota_mb = 0

    password = secrets.token_urlsafe(12)
    get_provider().create_ftp_account(username, password, home_dir, quota_mb)
    db.add(FtpAccount(owner_id=user.id, username=username,
                      password_enc=crypto.encrypt(password),
                      home_dir=home_dir, quota_mb=quota_mb))
    db.commit()
    # Stash the plaintext password to show once — we never store it in the clear.
    request.session["new_ftp_cred"] = {"username": username, "password": password,
                                       "home_dir": home_dir}
    _flash(request, f"✅ FTP account '{username}' created.")
    return RedirectResponse("/ftp", status_code=303)


@router.post("/{ftp_id}/password")
def reset_ftp_password(
    request: Request,
    ftp_id: int,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    acct = db.get(FtpAccount, ftp_id)
    if acct is None or acct.owner_id != user.id:
        _flash(request, "❌ FTP account not found.")
        return RedirectResponse("/ftp", status_code=303)
    password = secrets.token_urlsafe(12)
    get_provider().set_ftp_password(acct.username, password)
    acct.password_enc = crypto.encrypt(password)
    db.commit()
    request.session["new_ftp_cred"] = {"username": acct.username, "password": password,
                                       "home_dir": acct.home_dir}
    _flash(request, f"🔑 Password reset for '{acct.username}'.")
    return RedirectResponse("/ftp", status_code=303)


@router.post("/{ftp_id}/delete")
def delete_ftp(
    request: Request,
    ftp_id: int,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    acct = db.get(FtpAccount, ftp_id)
    if acct is None or acct.owner_id != user.id:
        _flash(request, "❌ FTP account not found.")
        return RedirectResponse("/ftp", status_code=303)
    get_provider().delete_ftp_account(acct.username)
    username = acct.username
    db.delete(acct)
    db.commit()
    _flash(request, f"🗑️ FTP account '{username}' removed.")
    return RedirectResponse("/ftp", status_code=303)
