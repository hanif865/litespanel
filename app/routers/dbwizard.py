"""Database Wizard — guided create-database-plus-user in one step.

Unlike the one-click Databases page (which auto-generates the user/password),
the wizard lets you name the database, choose the username, and set the
password yourself — cPanel's "MySQL Database Wizard" flow.
"""
from __future__ import annotations

import re

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import RedirectResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..db import get_db
from ..limits import database_limit_reached
from ..models import Database, User
from ..providers import get_provider
from ..security import current_user
from ..web import templates

router = APIRouter(prefix="/database-wizard", tags=["dbwizard"])

_DB_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_]{0,63}$")
_USER_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_]{0,63}$")


def _flash(request: Request, message: str) -> None:
    request.session["flash"] = message


@router.get("")
def wizard(request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)):
    flash = request.session.pop("flash", None)
    result = request.session.pop("wizard_result", None)
    return templates.TemplateResponse(
        request, "dbwizard.html", {"user": user, "active": "dbwizard", "flash": flash, "result": result}
    )


@router.post("/create")
def wizard_create(
    request: Request,
    db_name: str = Form(...),
    db_user: str = Form(...),
    password: str = Form(...),
    password2: str = Form(...),
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    db_name = db_name.strip()
    db_user = db_user.strip()

    if database_limit_reached(db, user):
        _flash(request, f"❌ Database limit reached ({user.eff_databases}).")
        return RedirectResponse("/database-wizard", status_code=303)
    if not _DB_RE.match(db_name):
        _flash(request, "❌ Database name: start with a letter; letters/digits/underscore.")
        return RedirectResponse("/database-wizard", status_code=303)
    if not _USER_RE.match(db_user):
        _flash(request, "❌ Username: start with a letter; letters/digits/underscore.")
        return RedirectResponse("/database-wizard", status_code=303)
    if len(password) < 6:
        _flash(request, "❌ Password must be at least 6 characters.")
        return RedirectResponse("/database-wizard", status_code=303)
    if password != password2:
        _flash(request, "❌ Passwords do not match.")
        return RedirectResponse("/database-wizard", status_code=303)
    if db.scalar(select(Database).where(Database.name == db_name)):
        _flash(request, f"❌ Database '{db_name}' already exists.")
        return RedirectResponse("/database-wizard", status_code=303)

    creds = get_provider().create_database(db_name, db_user, password)
    db.add(Database(name=db_name, db_user=db_user, owner_id=user.id))
    db.commit()
    # Show the connection details once (password not stored by the panel).
    request.session["wizard_result"] = {
        "name": creds.name, "user": creds.user, "password": creds.password,
        "host": creds.host, "port": creds.port,
    }
    _flash(request, f"✅ Database '{db_name}' and user '{db_user}' created with ALL PRIVILEGES.")
    return RedirectResponse("/database-wizard", status_code=303)
