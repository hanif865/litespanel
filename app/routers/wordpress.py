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
from ..models import Certificate, Database, Domain, Subdomain, User, WordPressApp
from ..providers import get_provider
from ..security import current_user
from ..web import templates

router = APIRouter(prefix="/wordpress", tags=["wordpress"])

_USER_RE = re.compile(r"^[A-Za-z0-9_.@ -]{1,60}$")
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def _flash(request: Request, message: str) -> None:
    request.session["flash"] = message


class _Target:
    """A place WordPress can be installed: a domain (root or subdirectory) or a
    subdomain. Unifies the two so the installer, listing and uninstall don't each
    special-case subdomains. `token` (\"d:5\" / \"s:3\") is what the form round-trips."""

    def __init__(self, domain: Domain, subdomain: Subdomain | None):
        self.domain = domain              # always the parent domain (ownership, DB)
        self.subdomain = subdomain        # set when the target is a subdomain

    @property
    def token(self) -> str:
        return f"s:{self.subdomain.id}" if self.subdomain else f"d:{self.domain.id}"

    @property
    def host(self) -> str:
        return self.subdomain.fqdn if self.subdomain else self.domain.name

    @property
    def docroot(self) -> Path:
        return Path(self.subdomain.docroot if self.subdomain else self.domain.docroot)

    @property
    def php_version(self) -> str:
        return self.subdomain.php_version if self.subdomain else self.domain.php_version

    @property
    def can_ssl(self) -> bool:
        # Only domains carry a Certificate in the panel; subdomains stay HTTP.
        return self.subdomain is None


def _resolve_target(db: Session, user: User, token: str) -> _Target | None:
    """Turn a form token (\"d:<id>\" / \"s:<id>\") into an owned _Target, or None."""
    try:
        kind, sid = token.split(":", 1)
        oid = int(sid)
    except (ValueError, AttributeError):
        return None
    if kind == "s":
        sub = db.get(Subdomain, oid)
        if sub is None or sub.parent.owner_id != user.id:
            return None
        return _Target(sub.parent, sub)
    dom = db.get(Domain, oid)
    if dom is None or dom.owner_id != user.id:
        return None
    return _Target(dom, None)


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
    """Every WordPress install this account has — panel-managed ones (any
    domain root, subdirectory or subdomain) plus any set up outside the panel
    (a wp-config.php sitting in a domain's document root)."""
    domains = db.scalars(
        select(Domain).where(Domain.owner_id == user.id).order_by(Domain.name)
    ).all()
    apps = db.scalars(
        select(WordPressApp).join(Domain).where(Domain.owner_id == user.id)
    ).all()
    installs = []
    seen = set()  # (domain_id, subdomain_id, path) already represented by a managed record
    for a in apps:
        idir = Path(a.subdomain.docroot) if a.subdomain_id else Path(a.domain.docroot)
        if a.path:
            idir = idir / a.path
        display_host = a.subdomain.fqdn if a.subdomain else a.domain.name
        installs.append({
            "domain": a.domain, "app": a, "managed": True, "path": a.path or "",
            "display_host": display_host,
            "subdomain": a.subdomain,
            "db_name": a.db_name or _wp_db_name(idir),
            "on_disk": (idir / "wp-config.php").exists(),
        })
        seen.add((a.domain_id, a.subdomain_id or 0, a.path or ""))
    for d in domains:
        if (d.id, 0, "") in seen:
            continue
        if (Path(d.docroot) / "wp-config.php").exists():   # root install we didn't create
            installs.append({
                "domain": d, "app": None, "managed": False, "path": "",
                "display_host": d.name, "subdomain": None,
                "db_name": _wp_db_name(Path(d.docroot)), "on_disk": True,
            })
    installs.sort(key=lambda i: (i["display_host"], i["path"]))
    return installs


@router.get("")
def wp_page(request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)):
    domains = db.scalars(
        select(Domain).where(Domain.owner_id == user.id).order_by(Domain.name)
    ).all()
    subdomains = db.scalars(
        select(Subdomain).join(Domain).where(Domain.owner_id == user.id).order_by(Subdomain.fqdn)
    ).all()
    installs = _list_installs(db, user)
    # Any domain OR subdomain can host WordPress — at its root or in a
    # subdirectory (Softaculous-style). Offer each as a "d:<id>"/"s:<id>" target.
    targets = [{"token": f"d:{d.id}", "name": d.name, "ssl": True} for d in domains]
    targets += [{"token": f"s:{s.id}", "name": s.fqdn, "ssl": False} for s in subdomains]
    return templates.TemplateResponse(
        request, "wordpress.html",
        {"user": user, "domains": domains, "targets": targets, "installs": installs,
         "active": "wordpress",
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
{extra}
if (!defined('ABSPATH')) define('ABSPATH', __DIR__ . '/');
require_once ABSPATH . 'wp-settings.php';
"""

_DIR_RE = re.compile(r"^[A-Za-z0-9_-]{1,32}$")
_VER_RE = re.compile(r"^\d+\.\d+(\.\d+)?$")


def _download_url(version: str) -> str:
    """WordPress zip URL for a chosen version ("latest" or e.g. 6.5.2)."""
    v = (version or "").strip().lower()
    if _VER_RE.match(v):
        return f"https://wordpress.org/wordpress-{v}.zip"
    return config.WORDPRESS_URL  # latest.zip


def _parse_protocol(protocol: str, domain_name: str) -> tuple[str, str]:
    """Return (scheme, host) from a Softaculous-style protocol choice."""
    scheme = "https" if protocol.startswith("https") else "http"
    host = f"www.{domain_name}" if "www." in protocol else domain_name
    return scheme, host

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


def _ensure_ssl(db: Session, domain: Domain) -> bool:
    """Best-effort: issue a Let's Encrypt cert for the domain so it can be
    served over HTTPS (this also creates the domain's own :443 vhost, which
    stops HTTPS requests from falling through to the panel). Returns True if the
    domain has a usable cert afterwards. Only meaningful on the linux provider
    and only when the domain's DNS already points at this server."""
    if domain.certificate:
        return True
    if config.PROVIDER != "linux":
        return False
    try:
        info = get_provider().issue_certificate(domain.name)
    except Exception:  # noqa: BLE001 — DNS not pointed yet, rate limit, etc.
        return False
    db.add(Certificate(
        domain_id=domain.id, issuer=info.issuer, issued_at=info.issued_at,
        expires_at=info.expires_at, cert_path=info.cert_path,
    ))
    domain.force_https = True
    try:
        get_provider().set_https_redirect(
            domain.name, domain.docroot, domain.php_version,
            domain.owner.system_user or domain.owner.username, True, True)
    except Exception:  # noqa: BLE001
        pass
    db.commit()
    return True


@router.post("/install")
def wp_install(
    request: Request,
    target: str = Form(""),
    domain_id: int | None = Form(None),
    protocol: str = Form("http://"),
    directory: str = Form(""),
    version: str = Form("latest"),
    site_title: str = Form("My WordPress Site"),
    site_description: str = Form(""),
    multisite: str = Form(""),
    disable_cron: str = Form(""),
    admin_user: str = Form(...),
    admin_password: str = Form(...),
    admin_email: str = Form(...),
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    # Target is a "d:<id>"/"s:<id>" token; fall back to the legacy domain_id
    # field so older forms/links keep working.
    tgt = _resolve_target(db, user, target or (f"d:{domain_id}" if domain_id else ""))
    if tgt is None:
        _flash(request, "❌ Install target not found.")
        return RedirectResponse("/wordpress", status_code=303)
    domain = tgt.domain
    if database_limit_reached(db, user):
        _flash(request, f"❌ Database limit reached ({user.eff_databases}).")
        return RedirectResponse("/wordpress", status_code=303)
    if not _USER_RE.match(admin_user.strip()) or len(admin_password) < 6 or not _EMAIL_RE.match(admin_email.strip()):
        _flash(request, "❌ Enter a valid admin username, a password (6+ chars) and email.")
        return RedirectResponse("/wordpress", status_code=303)

    directory = directory.strip().strip("/")
    if directory and not _DIR_RE.match(directory):
        _flash(request, "❌ Directory may only contain letters, digits, dashes and underscores.")
        return RedirectResponse("/wordpress", status_code=303)

    docroot = tgt.docroot
    install_dir = docroot / directory if directory else docroot
    if (install_dir / "wp-config.php").exists():
        where = f"{tgt.host}/{directory}" if directory else tgt.host
        _flash(request, f"❌ WordPress is already installed at {where}.")
        return RedirectResponse("/wordpress", status_code=303)

    multisite_on = bool(multisite)
    disable_cron_on = bool(disable_cron)
    want_https = protocol.startswith("https")

    # 0. If HTTPS was requested and there's no cert yet, try to obtain one now
    #    (also creates the :443 vhost so HTTPS won't fall through to the panel).
    #    Only domains carry certificates in the panel — subdomains stay on HTTP.
    ssl_note = ""
    if want_https and not tgt.can_ssl:
        want_https = False
        ssl_note = " (subdomains are served over HTTP — installed without SSL.)"
    elif want_https:
        if _ensure_ssl(db, domain):
            db.refresh(domain)
        else:
            want_https = False
            ssl_note = (" (couldn't get an SSL certificate — installed over HTTP. "
                        "Point the domain's DNS at this server, then issue SSL from the SSL page.)")
    scheme = "https" if want_https else "http"
    host = tgt.host
    if "www." in protocol and not tgt.subdomain:
        host = f"www.{tgt.host}"
    url_path = f"/{directory}" if directory else ""
    site_url = f"{scheme}://{host}{url_path}"

    # 1. Database + user
    suffix = secrets.token_hex(3)
    dbname, dbuser, dbpass = f"wp_{suffix}", f"wp_{suffix}_u"[:64], secrets.token_urlsafe(14)
    creds = get_provider().create_database(dbname, dbuser, dbpass)
    db.add(Database(name=dbname, db_user=dbuser,
                    db_password_enc=crypto.encrypt(dbpass), owner_id=user.id))
    db.commit()

    # 2. WordPress files (chosen version) into the install directory
    install_dir.mkdir(parents=True, exist_ok=True)
    try:
        if config.PROVIDER == "linux":
            with urllib.request.urlopen(_download_url(version), timeout=90) as r:
                data = r.read()
            with zipfile.ZipFile(io.BytesIO(data)) as zf:
                for member in zf.namelist():
                    if not member.startswith("wordpress/") or member.endswith("/"):
                        continue
                    target_path = (install_dir / member[len("wordpress/"):]).resolve()
                    if install_dir.resolve() not in target_path.parents:
                        continue
                    target_path.parent.mkdir(parents=True, exist_ok=True)
                    with zf.open(member) as s, open(target_path, "wb") as d:
                        d.write(s.read())
        else:
            (install_dir / "index.php").write_text(
                "<?php echo '<h1>WordPress is configured 🎉 (demo)</h1>';", encoding="utf-8")
    except Exception as exc:  # noqa: BLE001
        _flash(request, f"❌ WordPress download failed: {exc}")
        return RedirectResponse("/wordpress", status_code=303)

    # 3. wp-config.php (with optional multisite / cron tweaks)
    extra = []
    if disable_cron_on:
        extra.append("define('DISABLE_WP_CRON', true);")
    if multisite_on:
        extra.append("define('WP_ALLOW_MULTISITE', true);")
    (install_dir / "wp-config.php").write_text(
        _WP_CONFIG.format(name=creds.name, user=creds.user, password=creds.password,
                          host=creds.host, salts=_wp_salts(), extra="\n".join(extra)),
        encoding="utf-8")

    # 4. Full install via wp-cli (title + admin account, no browser wizard)
    sysuser = domain.owner.system_user or domain.owner.username
    install_cmd = "multisite-install" if multisite_on else "install"
    ok, out = get_provider().run_wp_cli(install_dir, sysuser, [
        "core", install_cmd, f"--url={site_url}", f"--title={site_title}",
        f"--admin_user={admin_user.strip()}", f"--admin_password={admin_password}",
        f"--admin_email={admin_email.strip()}", "--skip-email",
    ])
    if site_description.strip():
        get_provider().run_wp_cli(install_dir, sysuser,
                                  ["option", "update", "blogdescription", site_description.strip()])

    # 5. Auto-login mu-plugin + panel record
    login_secret = secrets.token_hex(24)
    mu = install_dir / "wp-content" / "mu-plugins"
    mu.mkdir(parents=True, exist_ok=True)
    (mu / "litespanel-autologin.php").write_text(_MU_PLUGIN.format(secret=login_secret), encoding="utf-8")
    get_provider().set_owner(install_dir, sysuser)

    sub_id = tgt.subdomain.id if tgt.subdomain else None
    db.query(WordPressApp).filter(
        WordPressApp.domain_id == domain.id,
        WordPressApp.subdomain_id == sub_id,
        WordPressApp.path == directory).delete()
    db.add(WordPressApp(domain_id=domain.id, subdomain_id=sub_id,
                        admin_user=admin_user.strip(),
                        admin_email=admin_email.strip(), login_secret=login_secret,
                        db_name=dbname, path=directory))
    db.commit()

    if config.PROVIDER == "linux" and not ok:
        _flash(request, f"⚠️ Files installed but wp-cli setup reported: {out[:200]}")
    else:
        _flash(request, f"✅ WordPress installed at {site_url} — use “Login” to open wp-admin.{ssl_note}")
    return RedirectResponse("/wordpress", status_code=303)


@router.get("/{app_id}/login")
def wp_login(app_id: int, user: User = Depends(current_user), db: Session = Depends(get_db)):
    app = db.get(WordPressApp, app_id)
    if app is None or app.domain.owner_id != user.id:
        return RedirectResponse("/wordpress", status_code=303)
    exp = int(time.time()) + 300
    sig = hmac.new(app.login_secret.encode(), f"{app.admin_user}.{exp}".encode(), hashlib.sha256).hexdigest()
    token = f"{app.admin_user}.{exp}.{sig}"
    # A subdomain install lives at its own fqdn over HTTP; a domain install uses
    # the domain name and HTTPS when it has a certificate.
    if app.subdomain_id:
        host, scheme = app.subdomain.fqdn, "http"
    else:
        host, scheme = app.domain.name, ("https" if app.domain.certificate else "http")
    base = f"{scheme}://{host}" + (f"/{app.path}" if app.path else "")
    return RedirectResponse(f"{base}/?litespanel_login={token}", status_code=303)


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
    path: str = Form(""),
    subdomain_id: int | None = Form(None),
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    """Softaculous-style Uninstall: remove the site's files AND drop its
    database + DB user. Works for panel-managed installs (any subdirectory) and
    ones set up outside the panel (DB name is read from wp-config.php)."""
    domain = db.get(Domain, domain_id)
    if domain is None or domain.owner_id != user.id:
        _flash(request, "❌ Site not found.")
        return RedirectResponse("/wordpress", status_code=303)

    path = path.strip().strip("/")
    subdomain = None
    if subdomain_id:
        subdomain = db.get(Subdomain, subdomain_id)
        if subdomain is None or subdomain.parent_id != domain.id:
            _flash(request, "❌ Subdomain not found.")
            return RedirectResponse("/wordpress", status_code=303)

    docroot = Path(subdomain.docroot if subdomain else domain.docroot)
    install_dir = docroot / path if path else docroot
    app = db.scalar(select(WordPressApp).where(
        WordPressApp.domain_id == domain.id,
        WordPressApp.subdomain_id == subdomain_id,
        WordPressApp.path == path))
    dbname = (app.db_name if app and app.db_name else None) or _wp_db_name(install_dir)

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

    # 2. Delete the WordPress files. A subdirectory install is removed whole; a
    #    root install has its contents emptied (the document root is kept).
    try:
        if path:
            import shutil
            target = install_dir.resolve()
            if not target.is_dir() or len(target.parts) < 4 or target == docroot.resolve():
                raise ValueError(f"refusing to remove unsafe path: {target}")
            shutil.rmtree(target, ignore_errors=True)
        else:
            _wipe_docroot(docroot)
    except Exception as exc:  # noqa: BLE001
        _flash(request, f"❌ Could not remove files: {exc}")
        return RedirectResponse("/wordpress", status_code=303)

    # 3. Forget the panel record.
    if app:
        db.delete(app)
    db.commit()

    where = f"{subdomain.fqdn if subdomain else domain.name}"
    if path:
        where += f"/{path}"
    _flash(request, f"🗑️ Uninstalled WordPress from {where}{dropped}.")
    return RedirectResponse("/wordpress", status_code=303)
