"""MySQL/MariaDB database management."""
from __future__ import annotations

import re
import secrets

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import RedirectResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..db import get_db
from ..models import Database, User
from ..limits import database_limit_reached
from ..providers import get_provider
from ..security import current_user
from ..web import templates

router = APIRouter(prefix="/databases", tags=["databases"])

_NAME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_]{0,63}$")


def _flash(request: Request, message: str) -> None:
    request.session["flash"] = message


@router.get("")
def list_databases(request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)):
    rows = db.scalars(
        select(Database).where(Database.owner_id == user.id).order_by(Database.name)
    ).all()
    flash = request.session.pop("flash", None)
    # A freshly generated password shown once after creation.
    new_cred = request.session.pop("new_db_cred", None)
    return templates.TemplateResponse(
        request,
        "databases.html",
        {"user": user, "databases": rows, "active": "databases", "flash": flash, "new_cred": new_cred},
    )


@router.post("/create")
def create_database(
    request: Request,
    name: str = Form(...),
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    if database_limit_reached(db, user):
        _flash(request, f"❌ Database limit reached ({user.max_databases}). Contact your provider.")
        return RedirectResponse("/databases", status_code=303)
    name = name.strip()
    if not _NAME_RE.match(name):
        _flash(request, "❌ Name must start with a letter; letters, digits, underscore only.")
        return RedirectResponse("/databases", status_code=303)
    if db.scalar(select(Database).where(Database.name == name)):
        _flash(request, f"❌ Database '{name}' already exists.")
        return RedirectResponse("/databases", status_code=303)

    db_user = f"{name}_u"[:64]
    password = secrets.token_urlsafe(12)
    creds = get_provider().create_database(name, db_user, password)
    db.add(Database(name=name, db_user=db_user, owner_id=user.id))
    db.commit()
    # Stash the plaintext password to show once — we never store it.
    request.session["new_db_cred"] = {
        "name": creds.name, "user": creds.user, "password": creds.password,
        "host": creds.host, "port": creds.port,
    }
    _flash(request, f"✅ Database '{name}' created.")
    return RedirectResponse("/databases", status_code=303)


@router.post("/{db_id}/delete")
def delete_database(
    request: Request,
    db_id: int,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    row = db.get(Database, db_id)
    if row is None or row.owner_id != user.id:
        _flash(request, "❌ Database not found.")
        return RedirectResponse("/databases", status_code=303)
    get_provider().drop_database(row.name, row.db_user)
    name = row.name
    db.delete(row)
    db.commit()
    _flash(request, f"🗑️ Database '{name}' dropped.")
    return RedirectResponse("/databases", status_code=303)
