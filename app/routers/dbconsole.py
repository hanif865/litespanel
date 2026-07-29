"""Database Manager — a phpMyAdmin-style console.

- If PANEL_PHPMYADMIN_URL is configured, embeds the real phpMyAdmin (iframe) and
  can auto-login as a database's own scoped MySQL user (like cPanel/Softaculous)
  — no username/password prompt. The credential is decrypted from the panel DB
  (see app/crypto.py) and posted to phpMyAdmin's cookie-auth login.
- Otherwise uses the built-in SQL console. In demo mode each database is a
  real SQLite file, so browsing tables and running queries actually works.
"""
from __future__ import annotations

import html
import re
import secrets
from pathlib import Path

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import config, crypto
from ..db import get_db
from ..models import Database, Domain, User, WordPressApp
from ..providers import get_provider
from ..security import current_user
from ..web import templates

_WP_DB_PASS_RE = re.compile(r"""define\(\s*['"]DB_PASSWORD['"]\s*,\s*['"]([^'"]*)['"]""")


def _password_for(db: Session, user: User, row: Database) -> str | None:
    """The MySQL password for a database's own user, for phpMyAdmin auto-login.

    Prefer the encrypted copy stored in the panel DB. If that's missing or can't
    be decrypted (e.g. a WordPress install from before we stored it), recover the
    real password from that site's wp-config.php — no password reset, so the live
    site keeps working — and cache it back encrypted for next time.
    """
    password = crypto.decrypt(row.db_password_enc)
    if password is not None:
        return password
    apps = db.scalars(
        select(WordPressApp).join(Domain).where(Domain.owner_id == user.id)
    ).all()
    for a in apps:
        if a.db_name != row.name:
            continue
        idir = Path(a.domain.docroot) / a.path if a.path else Path(a.domain.docroot)
        try:
            text = (idir / "wp-config.php").read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        m = _WP_DB_PASS_RE.search(text)
        if m:
            password = m.group(1)
            row.db_password_enc = crypto.encrypt(password)
            db.commit()
            return password
    return None

# NOTE: mounted at /database-manager, NOT /phpmyadmin — on the server nginx
# serves the real phpMyAdmin at /phpmyadmin, so any panel route under that path
# would be shadowed (never reach the app). The signon form still posts to the
# real phpMyAdmin via config.PHPMYADMIN_URL.
router = APIRouter(prefix="/database-manager", tags=["dbmanager"])


def _render(request, user, db, selected=None, result=None, sql=""):
    databases = db.scalars(
        select(Database).where(Database.owner_id == user.id).order_by(Database.name)
    ).all()
    if selected is None and databases:
        selected = databases[0]
    tables = [] if config.PHPMYADMIN_URL else (
        get_provider().db_tables(selected.name) if selected else [])
    return templates.TemplateResponse(
        request,
        "dbmanager.html",
        {
            "user": user, "active": "phpmyadmin",
            "phpmyadmin_url": config.PHPMYADMIN_URL,
            "databases": databases, "selected": selected,
            "tables": tables, "result": result, "sql": sql,
            "flash": request.session.pop("flash", None),
        },
    )


@router.get("")
def index(
    request: Request,
    db_name: str | None = None,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    selected = None
    if db_name:
        selected = db.scalar(
            select(Database).where(Database.owner_id == user.id, Database.name == db_name)
        )
    return _render(request, user, db, selected=selected)


@router.get("/signon")
def signon(
    db_name: str,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    """Return a tiny page that auto-submits this database's credentials to
    phpMyAdmin's cookie-auth login, landing the user straight in their DB.

    Same-origin POST (phpMyAdmin is served under /phpmyadmin on this host), so
    the password never leaves the server's own origin — same as typing it into
    phpMyAdmin's own login form."""
    if not config.PHPMYADMIN_URL:
        raise HTTPException(status_code=404, detail="phpMyAdmin not configured.")
    row = db.scalar(
        select(Database).where(Database.owner_id == user.id, Database.name == db_name)
    )
    if row is None:
        raise HTTPException(status_code=404, detail="Database not found.")
    password = _password_for(db, user, row)
    if password is None:
        # No usable credential (older non-WordPress DB) — send them to the normal
        # login form; the Database Manager offers "Enable auto-login" for these.
        return HTMLResponse(
            f'<meta http-equiv="refresh" content="0;url={html.escape(config.PHPMYADMIN_URL)}">'
        )
    action = f"{config.PHPMYADMIN_URL}/index.php"
    page = f"""<!doctype html><html><head><meta charset="utf-8"><title>Signing in…</title></head>
<body style="font-family:sans-serif;color:#666;padding:2rem">Opening phpMyAdmin…
<form id="f" method="post" action="{html.escape(action, quote=True)}">
  <input type="hidden" name="pma_username" value="{html.escape(row.db_user, quote=True)}">
  <input type="hidden" name="pma_password" value="{html.escape(password, quote=True)}">
  <input type="hidden" name="server" value="1">
  <input type="hidden" name="db" value="{html.escape(row.name, quote=True)}">
</form>
<script>document.getElementById('f').submit();</script></body></html>"""
    return HTMLResponse(page)


@router.post("/enable-autologin")
def enable_autologin(
    request: Request,
    db_name: str = Form(...),
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    """Enable auto-login for a database created before this feature existed by
    resetting its MySQL user's password and storing it (encrypted).

    Note: this changes the database user's password, so any app already using
    it (e.g. a WordPress wp-config.php) must be updated to the new password.
    """
    row = db.scalar(
        select(Database).where(Database.owner_id == user.id, Database.name == db_name)
    )
    if row is None:
        request.session["flash"] = "❌ Database not found."
        return RedirectResponse("/database-manager", status_code=303)
    new_password = secrets.token_urlsafe(12)
    try:
        get_provider().reset_db_password(row.name, row.db_user, new_password)
    except Exception as exc:  # noqa: BLE001
        request.session["flash"] = f"❌ Could not reset the database password: {exc}"
        return RedirectResponse(f"/database-manager?db_name={row.name}", status_code=303)
    row.db_password_enc = crypto.encrypt(new_password)
    db.commit()
    request.session["flash"] = (
        f"✅ Auto-login enabled for {row.name}. If an app used this database's "
        f"old password, update it to: {new_password}")
    return RedirectResponse(f"/database-manager?db_name={row.name}", status_code=303)


@router.post("/query")
def run_query(
    request: Request,
    db_name: str = Form(...),
    sql: str = Form(...),
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    # When real phpMyAdmin is wired up, the built-in console is disabled — use
    # phpMyAdmin (which authenticates as the database's own scoped MySQL user)
    # instead of this passthrough.
    if config.PHPMYADMIN_URL:
        raise HTTPException(status_code=404, detail="Use phpMyAdmin.")
    selected = db.scalar(
        select(Database).where(Database.owner_id == user.id, Database.name == db_name)
    )
    if selected is None:
        request.session["flash"] = "❌ Database not found."
        return RedirectResponse("/database-manager", status_code=303)
    result = get_provider().db_execute(selected.name, sql)
    return _render(request, user, db, selected=selected, result=result, sql=sql)
