"""PostgreSQL database management.

Mirrors the MySQL databases router but for PostgreSQL: each database gets a
dedicated owning role, and the plaintext password is shown once at creation
(stored encrypted at rest, never in the clear). The provider does the real
work — psql on Linux, an inspectable SQLite mirror in the demo.
"""
from __future__ import annotations

import re
import secrets

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import RedirectResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import crypto
from ..db import get_db
from ..models import PgDatabase, User
from ..limits import pg_database_limit_reached
from ..providers import get_provider
from ..security import current_user
from ..web import templates

router = APIRouter(prefix="/pgsql", tags=["pgsql"])

_NAME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_]{0,63}$")


def _flash(request: Request, message: str) -> None:
    request.session["flash"] = message


@router.get("")
def list_pg_databases(request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)):
    rows = db.scalars(
        select(PgDatabase).where(PgDatabase.owner_id == user.id).order_by(PgDatabase.name)
    ).all()
    flash = request.session.pop("flash", None)
    new_cred = request.session.pop("new_pg_cred", None)
    available = get_provider().pg_available()
    return templates.TemplateResponse(
        request,
        "pg_databases.html",
        {"user": user, "databases": rows, "active": "pgsql", "flash": flash,
         "new_cred": new_cred, "available": available},
    )


@router.post("/create")
def create_pg_database(
    request: Request,
    name: str = Form(...),
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    if pg_database_limit_reached(db, user):
        _flash(request, f"❌ Database limit reached ({user.eff_databases}). Contact your provider.")
        return RedirectResponse("/pgsql", status_code=303)
    name = name.strip()
    if not _NAME_RE.match(name):
        _flash(request, "❌ Name must start with a letter; letters, digits, underscore only.")
        return RedirectResponse("/pgsql", status_code=303)
    if db.scalar(select(PgDatabase).where(PgDatabase.name == name)):
        _flash(request, f"❌ Database '{name}' already exists.")
        return RedirectResponse("/pgsql", status_code=303)

    db_user = f"{name}_u"[:64]
    password = secrets.token_urlsafe(12)
    try:
        creds = get_provider().create_pg_database(name, db_user, password)
    except Exception as exc:  # noqa: BLE001 — surface the psql error to the admin
        _flash(request, f"❌ Could not create database: {exc}")
        return RedirectResponse("/pgsql", status_code=303)

    db.add(PgDatabase(name=name, db_user=db_user,
                      db_password_enc=crypto.encrypt(password), owner_id=user.id))
    db.commit()
    request.session["new_pg_cred"] = {
        "name": creds.name, "user": creds.user, "password": creds.password,
        "host": creds.host, "port": creds.port,
    }
    _flash(request, f"✅ PostgreSQL database '{name}' created.")
    return RedirectResponse("/pgsql", status_code=303)


@router.post("/{db_id}/delete")
def delete_pg_database(
    request: Request,
    db_id: int,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    row = db.get(PgDatabase, db_id)
    if row is None or row.owner_id != user.id:
        _flash(request, "❌ Database not found.")
        return RedirectResponse("/pgsql", status_code=303)
    try:
        get_provider().drop_pg_database(row.name, row.db_user)
    except Exception as exc:  # noqa: BLE001
        _flash(request, f"❌ Could not drop database: {exc}")
        return RedirectResponse("/pgsql", status_code=303)
    name = row.name
    db.delete(row)
    db.commit()
    _flash(request, f"🗑️ PostgreSQL database '{name}' dropped.")
    return RedirectResponse("/pgsql", status_code=303)
