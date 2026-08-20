"""MySQL/MariaDB database management."""
from __future__ import annotations

import re
import secrets

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import RedirectResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import crypto, db_privileges
from ..db import get_db
from ..models import Database, DatabaseGrant, DatabaseUser, User
from ..limits import database_limit_reached
from ..providers import get_provider
from ..security import current_user
from ..web import templates

router = APIRouter(prefix="/databases", tags=["databases"])

_NAME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_]{0,63}$")
# Standalone DB usernames follow the same identifier rule as database names, so
# they can never inject when interpolated into a CREATE USER / GRANT statement.
_USER_RE = _NAME_RE


def _flash(request: Request, message: str) -> None:
    request.session["flash"] = message


def _own_user(db: Session, user: User, user_id: int) -> DatabaseUser | None:
    row = db.get(DatabaseUser, user_id)
    return row if row and row.owner_id == user.id else None


def _own_db(db: Session, user: User, db_id: int) -> Database | None:
    row = db.get(Database, db_id)
    return row if row and row.owner_id == user.id else None


def _own_grant(db: Session, user: User, grant_id: int) -> DatabaseGrant | None:
    row = db.get(DatabaseGrant, grant_id)
    if row is None or row.user.owner_id != user.id or row.database.owner_id != user.id:
        return None
    return row


@router.get("")
def list_databases(request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)):
    rows = db.scalars(
        select(Database).where(Database.owner_id == user.id).order_by(Database.name)
    ).all()
    users = db.scalars(
        select(DatabaseUser).where(DatabaseUser.owner_id == user.id).order_by(DatabaseUser.username)
    ).all()
    flash = request.session.pop("flash", None)
    # A freshly generated password shown once after creation.
    new_cred = request.session.pop("new_db_cred", None)
    return templates.TemplateResponse(
        request,
        "databases.html",
        {"user": user, "databases": rows, "db_users": users,
         "privileges": db_privileges.MYSQL_PRIVILEGES, "all_priv": db_privileges.ALL,
         "active": "databases", "flash": flash, "new_cred": new_cred},
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
    db.add(Database(name=name, db_user=db_user,
                    db_password_enc=crypto.encrypt(password), owner_id=user.id))
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


# --- Standalone users (cPanel "MySQL Users") ------------------------------
@router.post("/users/create")
def create_db_user(
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
        return RedirectResponse("/databases", status_code=303)
    if not password or password != password2:
        _flash(request, "❌ Passwords are required and must match.")
        return RedirectResponse("/databases", status_code=303)
    if db.scalar(select(DatabaseUser).where(DatabaseUser.username == username)):
        _flash(request, f"❌ User '{username}' already exists.")
        return RedirectResponse("/databases", status_code=303)
    try:
        get_provider().create_db_user(username, password)
    except Exception as exc:  # noqa: BLE001 — surface the mysql error
        _flash(request, f"❌ Could not create user: {exc}")
        return RedirectResponse("/databases", status_code=303)
    db.add(DatabaseUser(username=username, db_password_enc=crypto.encrypt(password),
                        owner_id=user.id))
    db.commit()
    _flash(request, f"✅ User '{username}' created.")
    return RedirectResponse("/databases", status_code=303)


@router.post("/users/{user_id}/password")
def set_db_user_password(
    request: Request,
    user_id: int,
    password: str = Form(...),
    password2: str = Form(""),
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    row = _own_user(db, user, user_id)
    if row is None:
        _flash(request, "❌ User not found.")
        return RedirectResponse("/databases", status_code=303)
    if not password or password != password2:
        _flash(request, "❌ Passwords are required and must match.")
        return RedirectResponse("/databases", status_code=303)
    try:
        get_provider().set_db_user_password(row.username, password)
    except Exception as exc:  # noqa: BLE001
        _flash(request, f"❌ Could not change password: {exc}")
        return RedirectResponse("/databases", status_code=303)
    row.db_password_enc = crypto.encrypt(password)
    db.commit()
    _flash(request, f"✅ Password changed for '{row.username}'.")
    return RedirectResponse("/databases", status_code=303)


@router.post("/users/{user_id}/delete")
def delete_db_user(
    request: Request,
    user_id: int,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    row = _own_user(db, user, user_id)
    if row is None:
        _flash(request, "❌ User not found.")
        return RedirectResponse("/databases", status_code=303)
    provider = get_provider()
    # Revoke each grant, then drop the user (dropping also clears its privileges,
    # but revoking first keeps the two engines' teardown paths identical).
    try:
        for grant in list(row.grants):
            provider.revoke_privileges(grant.database.name, row.username)
        provider.drop_db_user(row.username)
    except Exception as exc:  # noqa: BLE001
        _flash(request, f"❌ Could not delete user: {exc}")
        return RedirectResponse("/databases", status_code=303)
    username = row.username
    db.delete(row)  # cascades its grants
    db.commit()
    _flash(request, f"🗑️ User '{username}' deleted.")
    return RedirectResponse("/databases", status_code=303)


# --- Add User To Database (grants) ----------------------------------------
def _apply_grant(db: Session, grant: DatabaseGrant, dbname: str, username: str,
                 tokens: list[str]) -> None:
    """Normalize the requested privileges, push them to the server, and store
    the canonical CSV on the grant row. Raises ValueError on a bad token."""
    privs = db_privileges.normalize("mysql", tokens)
    get_provider().grant_privileges(dbname, username, privs)
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
        _flash(request, "❌ User or database not found.")
        return RedirectResponse("/databases", status_code=303)
    # Upsert: attaching an already-attached user just updates its privileges.
    grant = db.scalar(select(DatabaseGrant).where(
        DatabaseGrant.user_id == db_user.id, DatabaseGrant.database_id == database.id))
    if grant is None:
        grant = DatabaseGrant(user_id=db_user.id, database_id=database.id)
        db.add(grant)
    try:
        _apply_grant(db, grant, database.name, db_user.username, form.getlist("privileges"))
    except ValueError as exc:
        _flash(request, f"❌ {exc}")
        return RedirectResponse("/databases", status_code=303)
    except Exception as exc:  # noqa: BLE001
        _flash(request, f"❌ Could not apply privileges: {exc}")
        return RedirectResponse("/databases", status_code=303)
    db.commit()
    _flash(request, f"✅ '{db_user.username}' added to '{database.name}'.")
    return RedirectResponse("/databases", status_code=303)


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
        return RedirectResponse("/databases", status_code=303)
    try:
        _apply_grant(db, grant, grant.database.name, grant.user.username,
                     form.getlist("privileges"))
    except ValueError as exc:
        _flash(request, f"❌ {exc}")
        return RedirectResponse("/databases", status_code=303)
    except Exception as exc:  # noqa: BLE001
        _flash(request, f"❌ Could not apply privileges: {exc}")
        return RedirectResponse("/databases", status_code=303)
    db.commit()
    _flash(request, f"✅ Privileges updated for '{grant.user.username}' on '{grant.database.name}'.")
    return RedirectResponse("/databases", status_code=303)


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
        return RedirectResponse("/databases", status_code=303)
    uname, dname = grant.user.username, grant.database.name
    try:
        get_provider().revoke_privileges(dname, uname)
    except Exception as exc:  # noqa: BLE001
        _flash(request, f"❌ Could not revoke privileges: {exc}")
        return RedirectResponse("/databases", status_code=303)
    db.delete(grant)
    db.commit()
    _flash(request, f"🗑️ Revoked '{uname}' from '{dname}'.")
    return RedirectResponse("/databases", status_code=303)
