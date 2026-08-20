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

from .. import crypto, db_privileges
from ..db import get_db
from ..models import PgDatabase, PgGrant, PgUser, User
from ..limits import pg_database_limit_reached
from ..providers import get_provider
from ..security import current_user
from ..web import templates

router = APIRouter(prefix="/pgsql", tags=["pgsql"])

_NAME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_]{0,63}$")
_USER_RE = _NAME_RE


def _flash(request: Request, message: str) -> None:
    request.session["flash"] = message


def _own_user(db: Session, user: User, user_id: int) -> PgUser | None:
    row = db.get(PgUser, user_id)
    return row if row and row.owner_id == user.id else None


def _own_db(db: Session, user: User, db_id: int) -> PgDatabase | None:
    row = db.get(PgDatabase, db_id)
    return row if row and row.owner_id == user.id else None


def _own_grant(db: Session, user: User, grant_id: int) -> PgGrant | None:
    row = db.get(PgGrant, grant_id)
    if row is None or row.user.owner_id != user.id or row.database.owner_id != user.id:
        return None
    return row


@router.get("")
def list_pg_databases(request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)):
    rows = db.scalars(
        select(PgDatabase).where(PgDatabase.owner_id == user.id).order_by(PgDatabase.name)
    ).all()
    users = db.scalars(
        select(PgUser).where(PgUser.owner_id == user.id).order_by(PgUser.username)
    ).all()
    flash = request.session.pop("flash", None)
    new_cred = request.session.pop("new_pg_cred", None)
    available = get_provider().pg_available()
    return templates.TemplateResponse(
        request,
        "pg_databases.html",
        {"user": user, "databases": rows, "db_users": users,
         "privileges": db_privileges.PG_PRIVILEGES, "all_priv": db_privileges.ALL,
         "active": "pgsql", "flash": flash,
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


# --- Standalone roles -----------------------------------------------------
@router.post("/users/create")
def create_pg_user(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    password2: str = Form(""),
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    username = username.strip()
    if not _USER_RE.match(username):
        _flash(request, "❌ User must start with a letter; letters, digits, underscore only.")
        return RedirectResponse("/pgsql", status_code=303)
    if not password or password != password2:
        _flash(request, "❌ Passwords are required and must match.")
        return RedirectResponse("/pgsql", status_code=303)
    if db.scalar(select(PgUser).where(PgUser.username == username)):
        _flash(request, f"❌ Role '{username}' already exists.")
        return RedirectResponse("/pgsql", status_code=303)
    try:
        get_provider().create_pg_user(username, password)
    except Exception as exc:  # noqa: BLE001
        _flash(request, f"❌ Could not create role: {exc}")
        return RedirectResponse("/pgsql", status_code=303)
    db.add(PgUser(username=username, db_password_enc=crypto.encrypt(password),
                  owner_id=user.id))
    db.commit()
    _flash(request, f"✅ Role '{username}' created.")
    return RedirectResponse("/pgsql", status_code=303)


@router.post("/users/{user_id}/password")
def set_pg_user_password(
    request: Request,
    user_id: int,
    password: str = Form(...),
    password2: str = Form(""),
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    row = _own_user(db, user, user_id)
    if row is None:
        _flash(request, "❌ Role not found.")
        return RedirectResponse("/pgsql", status_code=303)
    if not password or password != password2:
        _flash(request, "❌ Passwords are required and must match.")
        return RedirectResponse("/pgsql", status_code=303)
    try:
        get_provider().set_pg_user_password(row.username, password)
    except Exception as exc:  # noqa: BLE001
        _flash(request, f"❌ Could not change password: {exc}")
        return RedirectResponse("/pgsql", status_code=303)
    row.db_password_enc = crypto.encrypt(password)
    db.commit()
    _flash(request, f"✅ Password changed for '{row.username}'.")
    return RedirectResponse("/pgsql", status_code=303)


@router.post("/users/{user_id}/delete")
def delete_pg_user(
    request: Request,
    user_id: int,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    row = _own_user(db, user, user_id)
    if row is None:
        _flash(request, "❌ Role not found.")
        return RedirectResponse("/pgsql", status_code=303)
    provider = get_provider()
    # A PG role can't be dropped while it still holds privileges — revoke every
    # grant first, then drop the role.
    try:
        for grant in list(row.grants):
            provider.revoke_pg_privileges(grant.database.name, row.username)
        provider.drop_pg_user(row.username)
    except Exception as exc:  # noqa: BLE001
        _flash(request, f"❌ Could not delete role: {exc}")
        return RedirectResponse("/pgsql", status_code=303)
    username = row.username
    db.delete(row)  # cascades its grants
    db.commit()
    _flash(request, f"🗑️ Role '{username}' deleted.")
    return RedirectResponse("/pgsql", status_code=303)


# --- Add Role To Database (grants) ----------------------------------------
def _apply_grant(db: Session, grant: PgGrant, dbname: str, username: str,
                 tokens: list[str]) -> None:
    privs = db_privileges.normalize("pg", tokens)
    get_provider().grant_pg_privileges(dbname, username, privs)
    grant.privileges = db_privileges.to_csv(privs)


@router.post("/grants/create")
async def create_grant(
    request: Request,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    form = await request.form()
    db_user = _own_user(db, user, int(form.get("user_id") or 0))
    database = _own_db(db, user, int(form.get("database_id") or 0))
    if db_user is None or database is None:
        _flash(request, "❌ Role or database not found.")
        return RedirectResponse("/pgsql", status_code=303)
    grant = db.scalar(select(PgGrant).where(
        PgGrant.user_id == db_user.id, PgGrant.database_id == database.id))
    if grant is None:
        grant = PgGrant(user_id=db_user.id, database_id=database.id)
        db.add(grant)
    try:
        _apply_grant(db, grant, database.name, db_user.username, form.getlist("privileges"))
    except ValueError as exc:
        _flash(request, f"❌ {exc}")
        return RedirectResponse("/pgsql", status_code=303)
    except Exception as exc:  # noqa: BLE001
        _flash(request, f"❌ Could not apply privileges: {exc}")
        return RedirectResponse("/pgsql", status_code=303)
    db.commit()
    _flash(request, f"✅ '{db_user.username}' added to '{database.name}'.")
    return RedirectResponse("/pgsql", status_code=303)


@router.post("/grants/{grant_id}/update")
async def update_grant(
    request: Request,
    grant_id: int,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    form = await request.form()
    grant = _own_grant(db, user, grant_id)
    if grant is None:
        _flash(request, "❌ Grant not found.")
        return RedirectResponse("/pgsql", status_code=303)
    try:
        _apply_grant(db, grant, grant.database.name, grant.user.username,
                     form.getlist("privileges"))
    except ValueError as exc:
        _flash(request, f"❌ {exc}")
        return RedirectResponse("/pgsql", status_code=303)
    except Exception as exc:  # noqa: BLE001
        _flash(request, f"❌ Could not apply privileges: {exc}")
        return RedirectResponse("/pgsql", status_code=303)
    db.commit()
    _flash(request, f"✅ Privileges updated for '{grant.user.username}' on '{grant.database.name}'.")
    return RedirectResponse("/pgsql", status_code=303)


@router.post("/grants/{grant_id}/delete")
def delete_grant(
    request: Request,
    grant_id: int,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    grant = _own_grant(db, user, grant_id)
    if grant is None:
        _flash(request, "❌ Grant not found.")
        return RedirectResponse("/pgsql", status_code=303)
    uname, dname = grant.user.username, grant.database.name
    try:
        get_provider().revoke_pg_privileges(dname, uname)
    except Exception as exc:  # noqa: BLE001
        _flash(request, f"❌ Could not revoke privileges: {exc}")
        return RedirectResponse("/pgsql", status_code=303)
    db.delete(grant)
    db.commit()
    _flash(request, f"🗑️ Revoked '{uname}' from '{dname}'.")
    return RedirectResponse("/pgsql", status_code=303)
