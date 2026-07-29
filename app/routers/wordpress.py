"""1-click WordPress installer (Softaculous-style) + password-less auto-login.

Install: creates a database + user, downloads WordPress, writes wp-config.php,
then runs `wp core install` (wp-cli) to fully set up the site — title and admin
account included, no browser wizard needed. A drop-in mu-plugin enables the
panel's one-click "Login" to wp-admin via a short-lived signed token.
"""
from __future__ import annotations

import hashlib
import hmac
import io
import re
import secrets
import time
import urllib.request
import zipfile
from pathlib import Path

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import RedirectResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import config, crypto
from ..db import get_db
from ..limits import database_limit_reached
from ..models import Database, Domain, User, WordPressApp
from ..providers import get_provider
from ..security import current_user
from ..web import templates

router = APIRouter(prefix="/wordpress", tags=["wordpress"])

_USER_RE = re.compile(r"^[A-Za-z0-9_.@ -]{1,60}$")
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def _flash(request: Request, message: str) -> None:
    request.session["flash"] = message


_DB_NAME_RE = re.compile(r"""define\(\s*['"]DB_NAME['"]\s*,\s*['"]([^'"]+)['"]""")


def _wp_db_name(docroot: Path) -> str | None:
    """Read DB_NAME out of an existing wp-config.php (installs we didn't create)."""
    try:
        text = (docroot / "wp-config.php").read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return None
    m = _DB_NAME_RE.search(text)
    return m.group(1) if m else None


def _list_installs(db: Session, user: User) -> list[dict]:
    """Every WordPress install this account has — including ones set up outside
    the panel — detected by a wp-config.php in the domain's document root."""
    domains = db.scalars(
        select(Domain).where(Domain.owner_id == user.id).order_by(Domain.name)
    ).all()
    apps = {a.domain_id: a for a in db.scalars(
        select(WordPressApp).join(Domain).where(Domain.owner_id == user.id)
    ).all()}
    installs = []
    for d in domains:
        app = apps.get(d.id)
        has_config = (Path(d.docroot) / "wp-config.php").exists()
        if not app and not has_config:
            continue  # no WordPress here
        installs.append({
            "domain": d,
            "app": app,                       # None for un-managed (no auto-login)
            "managed": app is not None,
            "db_name": (app.db_name if app and app.db_name else _wp_db_name(Path(d.docroot))),
            "on_disk": has_config,
        })
    return installs


@router.get("")
def wp_page(request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)):
    domains = db.scalars(
        select(Domain).where(Domain.owner_id == user.id).order_by(Domain.name)
    ).all()
    installs = _list_installs(db, user)
    installed_ids = {i["domain"].id for i in installs}
    # Offer install only on domains that don't already have WordPress.
    free_domains = [d for d in domains if d.id not in installed_ids]
    return templates.TemplateResponse(
        request, "wordpress.html",
        {"user": user, "domains": free_domains, "installs": installs, "active": "wordpress",
         "flash": request.session.pop("flash", None), "creds": request.session.pop("wp_creds", None)},
    )


def _wp_salts() -> str:
    try:
        with urllib.request.urlopen("https://api.wordpress.org/secret-key/1.1/salt/", timeout=10) as r:
            return r.read().decode()
    except Exception:  # noqa: BLE001
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

_MU_PLUGIN = """<?php
/* LitesPanel auto-login — verifies a short-lived signed token, then logs in. */
add_action('init', function () {{
    if (empty($_GET['litespanel_login'])) return;
    $parts = explode('.', $_GET['litespanel_login']);
    if (count($parts) !== 3) return;
    list($user, $exp, $sig) = $parts;
    if (time() > intval($exp)) return;
    $expected = hash_hmac('sha256', $user . '.' . $exp, '{secret}');
    if (!hash_equals($expected, $sig)) return;
    $u = get_user_by('login', $user);
    if (!$u) return;
    wp_set_auth_cookie($u->ID, true);
    wp_safe_redirect(admin_url());
    exit;
}});
"""


@router.post("/install")
def wp_install(
    request: Request,
    domain_id: int = Form(...),
    site_title: str = Form("My WordPress Site"),
    admin_user: str = Form(...),
    admin_password: str = Form(...),
    admin_email: str = Form(...),
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
    if not _USER_RE.match(admin_user.strip()) or len(admin_password) < 6 or not _EMAIL_RE.match(admin_email.strip()):
        _flash(request, "❌ Enter a valid admin username, a password (6+ chars) and email.")
        return RedirectResponse("/wordpress", status_code=303)

    docroot = Path(domain.docroot)
    if (docroot / "wp-config.php").exists():
        _flash(request, "❌ WordPress is already installed in this domain.")
        return RedirectResponse("/wordpress", status_code=303)

    # 1. Database + user
    suffix = secrets.token_hex(3)
    dbname, dbuser, dbpass = f"wp_{suffix}", f"wp_{suffix}_u"[:64], secrets.token_urlsafe(14)
    creds = get_provider().create_database(dbname, dbuser, dbpass)
    db.add(Database(name=dbname, db_user=dbuser,
                    db_password_enc=crypto.encrypt(dbpass), owner_id=user.id))
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
                    target = (docroot / member[len("wordpress/"):]).resolve()
                    if docroot.resolve() not in target.parents:
                        continue
                    target.parent.mkdir(parents=True, exist_ok=True)
                    with zf.open(member) as s, open(target, "wb") as d:
                        d.write(s.read())
        else:
            (docroot / "index.php").write_text(
                "<?php echo '<h1>WordPress is configured 🎉 (demo)</h1>';", encoding="utf-8")
    except Exception as exc:  # noqa: BLE001
        _flash(request, f"❌ WordPress download failed: {exc}")
        return RedirectResponse("/wordpress", status_code=303)

    # 3. wp-config.php
    (docroot / "wp-config.php").write_text(
        _WP_CONFIG.format(name=creds.name, user=creds.user, password=creds.password,
                          host=creds.host, salts=_wp_salts()), encoding="utf-8")

    # 4. Full install via wp-cli (title + admin account, no browser wizard)
    sysuser = domain.owner.system_user or domain.owner.username
    scheme = "https" if domain.certificate else "http"
    ok, out = get_provider().run_wp_cli(docroot, sysuser, [
        "core", "install", f"--url={scheme}://{domain.name}", f"--title={site_title}",
        f"--admin_user={admin_user.strip()}", f"--admin_password={admin_password}",
        f"--admin_email={admin_email.strip()}", "--skip-email",
    ])

    # 5. Auto-login mu-plugin + panel record
    login_secret = secrets.token_hex(24)
    mu = docroot / "wp-content" / "mu-plugins"
    mu.mkdir(parents=True, exist_ok=True)
    (mu / "litespanel-autologin.php").write_text(_MU_PLUGIN.format(secret=login_secret), encoding="utf-8")
    get_provider().set_owner(docroot, sysuser)

    db.query(WordPressApp).filter(WordPressApp.domain_id == domain.id).delete()
    db.add(WordPressApp(domain_id=domain.id, admin_user=admin_user.strip(),
                        admin_email=admin_email.strip(), login_secret=login_secret,
                        db_name=dbname))
    db.commit()

    if config.PROVIDER == "linux" and not ok:
        _flash(request, f"⚠️ Files installed but wp-cli setup reported: {out[:200]}")
    else:
        _flash(request, f"✅ WordPress fully installed on {domain.name} — use “Login” to open wp-admin.")
    return RedirectResponse("/wordpress", status_code=303)


@router.get("/{app_id}/login")
def wp_login(app_id: int, user: User = Depends(current_user), db: Session = Depends(get_db)):
    app = db.get(WordPressApp, app_id)
    if app is None or app.domain.owner_id != user.id:
        return RedirectResponse("/wordpress", status_code=303)
    exp = int(time.time()) + 300
    sig = hmac.new(app.login_secret.encode(), f"{app.admin_user}.{exp}".encode(), hashlib.sha256).hexdigest()
    token = f"{app.admin_user}.{exp}.{sig}"
    scheme = "https" if app.domain.certificate else "http"
    return RedirectResponse(f"{scheme}://{app.domain.name}/?litespanel_login={token}", status_code=303)


@router.post("/{app_id}/forget")
def wp_forget(request: Request, app_id: int, user: User = Depends(current_user), db: Session = Depends(get_db)):
    app = db.get(WordPressApp, app_id)
    if app and app.domain.owner_id == user.id:
        db.delete(app)
        db.commit()
        _flash(request, "Removed from the WordPress list (files kept).")
    return RedirectResponse("/wordpress", status_code=303)


def _wipe_docroot(docroot: Path) -> None:
    """Delete everything inside a document root (keeping the folder itself).

    Guarded so we can only ever empty a real, deep site directory — never a
    filesystem root or a shallow path.
    """
    import shutil

    root = docroot.resolve()
    if not root.is_dir() or len(root.parts) < 3:
        raise ValueError(f"refusing to wipe unsafe path: {root}")
    for child in root.iterdir():
        if child.is_dir() and not child.is_symlink():
            shutil.rmtree(child, ignore_errors=True)
        else:
            try:
                child.unlink()
            except OSError:
                pass


@router.post("/{domain_id}/uninstall")
def wp_uninstall(
    request: Request,
    domain_id: int,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    """Softaculous-style Uninstall: remove the site's files AND drop its
    database + DB user. Works for panel-managed installs and ones set up
    outside the panel (DB name is read from wp-config.php)."""
    domain = db.get(Domain, domain_id)
    if domain is None or domain.owner_id != user.id:
        _flash(request, "❌ Site not found.")
        return RedirectResponse("/wordpress", status_code=303)

    docroot = Path(domain.docroot)
    app = db.scalar(select(WordPressApp).where(WordPressApp.domain_id == domain.id))
    dbname = (app.db_name if app and app.db_name else None) or _wp_db_name(docroot)

    # 1. Drop the database + its scoped user (best effort).
    dropped = ""
    if dbname:
        row = db.scalar(select(Database).where(
            Database.owner_id == user.id, Database.name == dbname))
        db_user = row.db_user if row else f"{dbname}_u"[:64]
        try:
            get_provider().drop_database(dbname, db_user)
            dropped = f" and dropped database {dbname}"
        except Exception as exc:  # noqa: BLE001
            dropped = f" (database {dbname} could not be dropped: {exc})"
        if row:
            db.delete(row)

    # 2. Delete the WordPress files.
    try:
        _wipe_docroot(docroot)
    except Exception as exc:  # noqa: BLE001
        _flash(request, f"❌ Could not remove files: {exc}")
        return RedirectResponse("/wordpress", status_code=303)

    # 3. Forget the panel record.
    if app:
        db.delete(app)
    db.commit()

    _flash(request, f"🗑️ Uninstalled WordPress from {domain.name}{dropped}.")
    return RedirectResponse("/wordpress", status_code=303)
