"""1-click WordPress installer.

Creates a database + user, downloads WordPress into the domain's document
root, and writes a ready-to-run wp-config.php. On the demo provider (no MySQL)
it lays down a small stub so the flow is visible; on a real server it installs
WordPress for real.
"""
from __future__ import annotations

import io
import re
import secrets
import urllib.request
import zipfile
from pathlib import Path

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import RedirectResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import config
from ..db import get_db
from ..limits import database_limit_reached
from ..models import Database, Domain, User
from ..providers import get_provider
from ..security import current_user
from ..web import templates

router = APIRouter(prefix="/wordpress", tags=["wordpress"])


def _flash(request: Request, message: str) -> None:
    request.session["flash"] = message


@router.get("")
def wp_page(request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)):
    domains = db.scalars(
        select(Domain).where(Domain.owner_id == user.id).order_by(Domain.name)
    ).all()
    flash = request.session.pop("flash", None)
    creds = request.session.pop("wp_creds", None)
    return templates.TemplateResponse(
        request, "wordpress.html",
        {"user": user, "domains": domains, "active": "wordpress", "flash": flash, "creds": creds},
    )


def _wp_salts() -> str:
    try:
        with urllib.request.urlopen("https://api.wordpress.org/secret-key/1.1/salt/", timeout=10) as r:
            return r.read().decode()
    except Exception:  # noqa: BLE001 — fall back to locally generated keys
        keys = ["AUTH_KEY", "SECURE_AUTH_KEY", "LOGGED_IN_KEY", "NONCE_KEY",
                "AUTH_SALT", "SECURE_AUTH_SALT", "LOGGED_IN_SALT", "NONCE_SALT"]
        return "\n".join(f"define('{k}', '{secrets.token_urlsafe(48)}');" for k in keys)


_WP_CONFIG = """<?php
define('DB_NAME', '{name}');
define('DB_USER', '{user}');
define('DB_PASSWORD', '{password}');
define('DB_HOST', '{host}');
define('DB_CHARSET', 'utf8mb4');
define('DB_COLLATE', '');
{salts}
$table_prefix = 'wp_';
define('WP_DEBUG', false);
if (!defined('ABSPATH')) define('ABSPATH', __DIR__ . '/');
require_once ABSPATH . 'wp-settings.php';
"""


@router.post("/install")
def wp_install(
    request: Request,
    domain_id: int = Form(...),
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    domain = db.get(Domain, domain_id)
    if domain is None or domain.owner_id != user.id:
        _flash(request, "❌ Domain not found.")
        return RedirectResponse("/wordpress", status_code=303)
    if database_limit_reached(db, user):
        _flash(request, f"❌ Database limit reached ({user.eff_databases}).")
        return RedirectResponse("/wordpress", status_code=303)

    docroot = Path(domain.docroot)
    if any(docroot.glob("wp-*.php")) or (docroot / "wp-config.php").exists():
        _flash(request, "❌ WordPress (or another app) is already installed in this domain.")
        return RedirectResponse("/wordpress", status_code=303)

    # 1. Database + dedicated user
    suffix = secrets.token_hex(3)
    dbname = f"wp_{suffix}"
    dbuser = f"wp_{suffix}_u"[:64]
    dbpass = secrets.token_urlsafe(14)
    creds = get_provider().create_database(dbname, dbuser, dbpass)
    db.add(Database(name=dbname, db_user=dbuser, owner_id=user.id))
    db.commit()

    # 2. WordPress files
    try:
        if config.PROVIDER == "linux":
            with urllib.request.urlopen(config.WORDPRESS_URL, timeout=60) as r:
                data = r.read()
            with zipfile.ZipFile(io.BytesIO(data)) as zf:
                for member in zf.namelist():
                    if not member.startswith("wordpress/") or member.endswith("/"):
                        continue
                    rel = member[len("wordpress/"):]
                    target = (docroot / rel).resolve()
                    if docroot.resolve() not in target.parents:
                        continue
                    target.parent.mkdir(parents=True, exist_ok=True)
                    with zf.open(member) as s, open(target, "wb") as d:
                        d.write(s.read())
        else:
            # Demo: a small stub so the install is visible without MySQL/WP.
            (docroot / "index.php").write_text(
                "<?php /* WordPress (demo stub) — real install happens on a Linux server. */ "
                "echo '<h1>WordPress is configured 🎉</h1>';", encoding="utf-8"
            )
    except Exception as exc:  # noqa: BLE001
        _flash(request, f"❌ WordPress download/extract failed: {exc}")
        return RedirectResponse("/wordpress", status_code=303)

    # 3. wp-config.php
    (docroot / "wp-config.php").write_text(
        _WP_CONFIG.format(name=creds.name, user=creds.user, password=creds.password,
                          host=creds.host, salts=_wp_salts()),
        encoding="utf-8",
    )
    get_provider().set_owner(docroot, domain.owner.system_user or domain.owner.username)

    request.session["wp_creds"] = {
        "domain": domain.name, "db": creds.name, "db_user": creds.user, "db_password": creds.password,
    }
    _flash(request, f"✅ WordPress installed on {domain.name}! Visit the site to finish setup.")
    return RedirectResponse("/wordpress", status_code=303)
