"""WHM — the separate admin/reseller area (WebHost-Manager style).

A distinct shell from the cPanel-style user panel: admins and resellers create
and manage hosting accounts, set limits/packages, and (later) manage the server.
Every route is gated by require_manager (admins + resellers); resellers only see
and act on the accounts they created.

The heavy lifting is shared with the existing routers — account teardown lives in
accounts.terminate_account, reseller scoping/validation in routers.users, and
package visibility in routers.packages — so WHM is mostly a distinct presentation
plus a couple of admin-only actions (create-with-domain, password modification).
"""
from __future__ import annotations

import re
from pathlib import Path

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import RedirectResponse
from starlette.concurrency import run_in_threadpool
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .. import config, php_catalog, weblog
from ..accounts import account_home, terminate_account
from ..db import get_db
from ..limits import _count
from ..models import Database, Domain, EmailAccount, NodeApp, Package, PgDatabase, Subdomain, User
from ..providers import get_provider
from ..providers.base import SiteVhost, redis_tuning, web_fronting_enabled
from ..routers.dashboard import _meter
from ..routers.disk_usage import _dir_size
from ..routers.domains import _DOMAIN_RE
from ..routers.packages import _NAME_RE, visible_packages
from ..routers.users import _USERNAME_RE, _can_manage, _owned_package, _visible_users
from ..security import hash_password, require_admin, require_manager
from ..web import templates

router = APIRouter(prefix="/whm", tags=["whm"])


def _flash(request: Request, message: str) -> None:
    request.session["flash"] = message


# WHM "Create a New Account" result flags — cosmetic fields that round out the
# copy-paste credential block so it matches the cPanel/WHM account format.
_ACCOUNT_HASCGI = "y"          # the panel serves CGI/PHP for every account
_ACCOUNT_CPANEL_MOD = "jupiter"  # the panel's theme (like cPanel's Jupiter)
_ACCOUNT_IP_FLAG = "n"         # (n) = shared IP — no dedicated IP assigned


def _username_base(domain: str) -> str:
    """A cPanel-style base username from a domain: the second-level label,
    alphanumeric-only, lowercased, forced to start with a letter, and capped so
    there's room for a uniqueness suffix. Returns "" if nothing usable remains."""
    d = (domain or "").strip().lower().removeprefix("www.")
    label = d.split(".")[0]
    cleaned = re.sub(r"[^a-z0-9]", "", label)
    if not cleaned:
        return ""
    if not cleaned[0].isalpha():
        cleaned = "u" + cleaned
    return cleaned[:16]


def _suggest_username(db: Session, domain: str) -> str:
    """A unique username suggestion for a domain — the base, plus the smallest
    numeric suffix that isn't taken (webseojapan -> webseojapan2 -> ...)."""
    base = _username_base(domain)
    if not base:
        return ""
    candidate, n = base, 1
    while db.scalar(select(User.id).where(User.username == candidate)):
        n += 1
        suffix = str(n)
        candidate = f"{base[:16 - len(suffix)]}{suffix}"
    return candidate


# --- Dashboard ------------------------------------------------------------
@router.get("")
def dashboard(request: Request, manager: User = Depends(require_manager), db: Session = Depends(get_db)):
    users = _visible_users(db, manager)
    suspended = sum(1 for u in users if u.suspended)
    counts = {
        "total": len(users),
        "active": len(users) - suspended,
        "suspended": suspended,
        "packages": len(visible_packages(db, manager)),
    }
    flash = request.session.pop("flash", None)
    return templates.TemplateResponse(
        request, "whm/home.html",
        {"user": manager, "active": "home", "flash": flash,
         "server": get_provider().system_stats(), "counts": counts},
    )


# --- Accounts -------------------------------------------------------------
@router.get("/accounts")
def list_accounts(request: Request, manager: User = Depends(require_manager), db: Session = Depends(get_db)):
    users = _visible_users(db, manager)
    packages = visible_packages(db, manager)
    flash = request.session.pop("flash", None)
    return templates.TemplateResponse(
        request, "whm/accounts.html",
        {"user": manager, "users": users, "packages": packages,
         "active": "accounts", "flash": flash},
    )


@router.get("/accounts/new")
def new_account(request: Request, manager: User = Depends(require_manager), db: Session = Depends(get_db)):
    packages = visible_packages(db, manager)
    flash = request.session.pop("flash", None)
    return templates.TemplateResponse(
        request, "whm/create_account.html",
        {"user": manager, "packages": packages, "active": "create", "flash": flash},
    )


@router.post("/accounts/create")
def create_account(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    password2: str = Form(""),
    role: str = Form("user"),
    package_id: int = Form(0),
    max_domains: int = Form(0),
    max_databases: int = Form(0),
    max_email: int = Form(0),
    disk_quota_mb: int = Form(0),
    domain: str = Form(""),
    manager: User = Depends(require_manager),
    db: Session = Depends(get_db),
):
    username = username.strip().lower()
    if not _USERNAME_RE.match(username):
        _flash(request, "❌ Username: 3–32 chars, start with a letter, [a-z0-9_].")
        return RedirectResponse("/whm/accounts/new", status_code=303)
    if len(password) < 6:
        _flash(request, "❌ Password must be at least 6 characters.")
        return RedirectResponse("/whm/accounts/new", status_code=303)
    if password != password2:
        _flash(request, "❌ The two passwords do not match.")
        return RedirectResponse("/whm/accounts/new", status_code=303)
    if db.scalar(select(User).where(User.username == username)):
        _flash(request, f"❌ User '{username}' already exists.")
        return RedirectResponse("/whm/accounts/new", status_code=303)

    # The primary domain is required — like WHM/cPanel, every hosting account is
    # created around its main domain. Validated up front so nothing is half-made.
    domain = domain.strip().lower().removeprefix("www.")
    if not domain:
        _flash(request, "❌ A primary domain is required to create an account.")
        return RedirectResponse("/whm/accounts/new", status_code=303)
    if not _DOMAIN_RE.match(domain):
        _flash(request, f"❌ '{domain}' is not a valid domain name.")
        return RedirectResponse("/whm/accounts/new", status_code=303)
    if db.scalar(select(Domain).where(Domain.name == domain)):
        _flash(request, f"❌ Domain {domain} already exists.")
        return RedirectResponse("/whm/accounts/new", status_code=303)

    # Resellers may only create plain users; admins may also create resellers.
    if manager.role != "admin" or role not in ("user", "reseller"):
        role = "user"

    pkg = _owned_package(db, manager, package_id)
    new_user = User(
        username=username, password_hash=hash_password(password),
        role=role, is_admin=(role == "admin"), created_by_id=manager.id,
        package_id=pkg.id if pkg else None,
        max_domains=max(0, max_domains), max_databases=max(0, max_databases),
        max_email=max(0, max_email), disk_quota_mb=max(0, disk_quota_mb),
    )
    db.add(new_user)
    db.commit()

    # Every account created here gets an isolated system user (own /home + PHP
    # pool) and its primary domain provisioned as a live site.
    new_user.system_user = username
    db.commit()
    get_provider().ensure_account(username)

    home = account_home(db, new_user)
    docroot = home / domain / "public_html"
    get_provider().create_site(domain, docroot, "8.3", new_user.system_user)
    get_provider().reload_web()
    db.add(Domain(name=domain, owner_id=new_user.id, docroot=str(docroot),
                  php_version="8.3", is_primary=True))
    db.commit()

    # Stash the one-time credentials for the result page (WHM shows them once).
    # The plaintext password lives only in the manager's own session and is
    # popped on the very next view — never persisted anywhere.
    request.session["new_account"] = {
        "user_id": new_user.id,
        "username": username,
        "password": password,
        "domain": domain,
        "role": role,
        "package": pkg.name if pkg else "",
    }
    return RedirectResponse("/whm/accounts/created", status_code=303)


# --- Create-account helpers (declared before /accounts/{user_id}) ----------
@router.get("/accounts/suggest")
def suggest_username(
    domain: str = "",
    manager: User = Depends(require_manager),
    db: Session = Depends(get_db),
):
    """Live, unique username suggestion for the create-account form as the admin
    types the domain. Manager-gated like the rest of WHM (JSON response)."""
    return {"username": _suggest_username(db, domain)}


@router.get("/accounts/created")
def account_created(request: Request, manager: User = Depends(require_manager),
                    db: Session = Depends(get_db)):
    """Show a just-created account's credentials once, in the copy-paste WHM
    format. Pops the one-time session payload so a refresh (or a direct visit)
    can't replay it — it falls back to the accounts list instead."""
    data = request.session.pop("new_account", None)
    if not data:
        return RedirectResponse("/whm/accounts", status_code=303)
    acct = {
        **data,
        "ip": config.SERVER_IP,
        "ip_flag": _ACCOUNT_IP_FLAG,
        "hascgi": _ACCOUNT_HASCGI,
        "cpanel_mod": _ACCOUNT_CPANEL_MOD,
    }
    return templates.TemplateResponse(
        request, "whm/account_created.html",
        {"user": manager, "active": "create", "acct": acct},
    )


# --- Account Information (per-account detail) ------------------------------
# Read-only WHM view of one account: disk vs quota, recent traffic (parsed live
# from web logs — no persistent bandwidth counter exists yet), and how many
# domains / databases / email accounts it has vs its limits. Declared AFTER the
# static /accounts/new and /accounts/create so those aren't captured as an id.
@router.get("/accounts/{user_id}")
def account_detail(request: Request, user_id: int,
                   manager: User = Depends(require_manager), db: Session = Depends(get_db)):
    target = db.get(User, user_id)
    # Admins may open any account; resellers only the ones they created.
    if target is None or (manager.role != "admin" and target.created_by_id != manager.id):
        _flash(request, "❌ Account not found.")
        return RedirectResponse("/whm/accounts", status_code=303)

    provider = get_provider()
    domains = list(target.domains)
    primary = next((d for d in domains if d.is_primary), domains[0] if domains else None)

    # Per-domain disk footprint + recent traffic. Disk uses the bounded walk;
    # bandwidth is summed from the tail of each domain's access log (capped) so
    # a busy account can't stall the single worker.
    disk_bytes = 0
    bw_bytes = 0
    domain_rows = []
    for d in sorted(domains, key=lambda x: (not x.is_primary, x.name)):
        site = Path(d.docroot).parent  # /home/<user>/<domain>
        d_disk = _dir_size(site) if site.exists() else 0
        d_bw = weblog.parse_access_log(provider.read_access_log(d.name, max_lines=8000))["bandwidth_bytes"]
        disk_bytes += d_disk
        bw_bytes += d_bw
        domain_rows.append({
            "name": d.name, "is_primary": d.is_primary,
            "disk_display": weblog.human_bytes(d_disk),
            "bw_display": weblog.human_bytes(d_bw),
        })

    disk_used_mb = round(disk_bytes / (1024 * 1024), 1)

    # Resource counts. MySQL + PostgreSQL share one database quota (like cPanel).
    n_domains = len(domains)
    n_databases = _count(db, Database, target.id) + _count(db, PgDatabase, target.id)
    n_subdomains = db.scalar(
        select(func.count()).select_from(Subdomain).join(Domain).where(Domain.owner_id == target.id)
    ) or 0
    owned = select(Domain.id).where(Domain.owner_id == target.id).scalar_subquery()
    n_email = db.scalar(
        select(func.count()).select_from(EmailAccount).where(EmailAccount.domain_id.in_(owned))
    ) or 0

    unlimited = target.unlimited
    usage = {
        "disk": _meter(disk_used_mb, 0 if unlimited else target.eff_disk_mb),
        "domains": _meter(n_domains, 0 if unlimited else target.eff_domains),
        "databases": _meter(n_databases, 0 if unlimited else target.eff_databases),
        "email": _meter(n_email, 0 if unlimited else target.eff_email),
    }

    if primary:
        home_dir = str(Path(primary.docroot).parent.parent)  # /home/<user>
    elif target.system_user:
        home_dir = f"/home/{target.system_user}"
    else:
        home_dir = "—"

    flash = request.session.pop("flash", None)
    return templates.TemplateResponse(
        request, "whm/account_detail.html",
        {"user": manager, "target": target, "active": "accounts", "flash": flash,
         "primary_domain": primary.name if primary else None,
         "usage": usage, "disk_used_mb": disk_used_mb,
         "bandwidth_display": weblog.human_bytes(bw_bytes),
         "counts": {"domains": n_domains, "databases": n_databases,
                    "subdomains": n_subdomains, "email": n_email},
         "home_dir": home_dir, "domain_rows": domain_rows,
         "package_name": target.package.name if target.package else None},
    )


@router.post("/accounts/{user_id}/password")
def modify_password(
    request: Request, user_id: int,
    password: str = Form(...), password2: str = Form(""),
    manager: User = Depends(require_manager), db: Session = Depends(get_db),
):
    target = db.get(User, user_id)
    if target is None or not _can_manage(manager, target):
        _flash(request, "❌ Not allowed.")
        return RedirectResponse("/whm/accounts", status_code=303)
    if len(password) < 6:
        _flash(request, "❌ Password must be at least 6 characters.")
        return RedirectResponse("/whm/accounts", status_code=303)
    if password != password2:
        _flash(request, "❌ The two passwords do not match.")
        return RedirectResponse("/whm/accounts", status_code=303)
    target.password_hash = hash_password(password)
    db.commit()
    _flash(request, f"🔒 Password updated for {target.username}.")
    return RedirectResponse("/whm/accounts", status_code=303)


@router.post("/accounts/{user_id}/package")
def change_package(
    request: Request, user_id: int, package_id: int = Form(0),
    manager: User = Depends(require_manager), db: Session = Depends(get_db),
):
    target = db.get(User, user_id)
    if target is None or not _can_manage(manager, target):
        _flash(request, "❌ Not allowed.")
        return RedirectResponse("/whm/accounts", status_code=303)
    pkg = _owned_package(db, manager, package_id)
    target.package_id = pkg.id if pkg else None
    db.commit()
    _flash(request, f"✅ {target.username} → {pkg.name if pkg else 'custom limits'}.")
    return RedirectResponse("/whm/accounts", status_code=303)


@router.post("/accounts/{user_id}/suspend")
def suspend_account(request: Request, user_id: int,
                    manager: User = Depends(require_manager), db: Session = Depends(get_db)):
    return _set_suspended(request, user_id, True, manager, db)


@router.post("/accounts/{user_id}/unsuspend")
def unsuspend_account(request: Request, user_id: int,
                      manager: User = Depends(require_manager), db: Session = Depends(get_db)):
    return _set_suspended(request, user_id, False, manager, db)


def _set_suspended(request, user_id, value, manager, db):
    target = db.get(User, user_id)
    if target is None or not _can_manage(manager, target):
        _flash(request, "❌ Not allowed.")
        return RedirectResponse("/whm/accounts", status_code=303)
    target.suspended = value
    db.commit()
    _flash(request, f"{'⏸️ Suspended' if value else '▶️ Reactivated'} {target.username}.")
    return RedirectResponse("/whm/accounts", status_code=303)


@router.post("/accounts/{user_id}/terminate")
def terminate(request: Request, user_id: int,
              manager: User = Depends(require_manager), db: Session = Depends(get_db)):
    target = db.get(User, user_id)
    if target is None or not _can_manage(manager, target):
        _flash(request, "❌ Not allowed.")
        return RedirectResponse("/whm/accounts", status_code=303)
    username = terminate_account(db, target)
    _flash(request, f"🗑️ Account '{username}' and all its resources removed.")
    return RedirectResponse("/whm/accounts", status_code=303)


# --- Packages -------------------------------------------------------------
@router.get("/packages")
def list_packages(request: Request, manager: User = Depends(require_manager), db: Session = Depends(get_db)):
    packages = visible_packages(db, manager)
    flash = request.session.pop("flash", None)
    return templates.TemplateResponse(
        request, "whm/packages.html",
        {"user": manager, "packages": packages, "active": "packages", "flash": flash},
    )


@router.post("/packages/create")
def create_package(
    request: Request,
    name: str = Form(...),
    max_domains: int = Form(0),
    max_databases: int = Form(0),
    max_email: int = Form(0),
    disk_quota_mb: int = Form(0),
    manager: User = Depends(require_manager),
    db: Session = Depends(get_db),
):
    name = name.strip()
    if not _NAME_RE.match(name):
        _flash(request, "❌ Invalid package name.")
        return RedirectResponse("/whm/packages", status_code=303)
    if db.scalar(select(Package).where(Package.owner_id == manager.id, Package.name == name)):
        _flash(request, f"❌ Package '{name}' already exists.")
        return RedirectResponse("/whm/packages", status_code=303)
    db.add(Package(
        name=name, owner_id=manager.id,
        max_domains=max(0, max_domains), max_databases=max(0, max_databases),
        max_email=max(0, max_email), disk_quota_mb=max(0, disk_quota_mb),
    ))
    db.commit()
    _flash(request, f"✅ Package '{name}' created.")
    return RedirectResponse("/whm/packages", status_code=303)


@router.post("/packages/{package_id}/update")
def update_package(
    request: Request, package_id: int,
    max_domains: int = Form(0),
    max_databases: int = Form(0),
    max_email: int = Form(0),
    disk_quota_mb: int = Form(0),
    manager: User = Depends(require_manager),
    db: Session = Depends(get_db),
):
    pkg = db.get(Package, package_id)
    if pkg is None or (manager.role != "admin" and pkg.owner_id != manager.id):
        _flash(request, "❌ Not allowed.")
        return RedirectResponse("/whm/packages", status_code=303)
    pkg.max_domains = max(0, max_domains)
    pkg.max_databases = max(0, max_databases)
    pkg.max_email = max(0, max_email)
    pkg.disk_quota_mb = max(0, disk_quota_mb)
    db.commit()
    _flash(request, f"✅ Package '{pkg.name}' updated — all its accounts now use the new limits.")
    return RedirectResponse("/whm/packages", status_code=303)


@router.post("/packages/{package_id}/delete")
def delete_package(
    request: Request, package_id: int,
    manager: User = Depends(require_manager), db: Session = Depends(get_db),
):
    pkg = db.get(Package, package_id)
    if pkg is None or (manager.role != "admin" and pkg.owner_id != manager.id):
        _flash(request, "❌ Not allowed.")
        return RedirectResponse("/whm/packages", status_code=303)
    if pkg.users:
        _flash(request, f"❌ '{pkg.name}' is assigned to {len(pkg.users)} account(s). Reassign them first.")
        return RedirectResponse("/whm/packages", status_code=303)
    name = pkg.name
    db.delete(pkg)
    db.commit()
    _flash(request, f"🗑️ Package '{name}' deleted.")
    return RedirectResponse("/whm/packages", status_code=303)


# --- Server Software (system installs — admin only) -----------------------
# These shell out as root (apt-get / NodeSource), so they live in WHM and are
# gated by require_admin — never a reseller. The user panel keeps only the
# per-account settings (PHP version, extension toggles, Node app deploy).
_SOFTWARE_PHP = php_catalog.DEFAULT_PHP_VERSION


@router.get("/software")
def software(request: Request, admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    provider = get_provider()
    php_version = _SOFTWARE_PHP
    installed = provider.list_installed_extensions(php_version)
    # Only extensions that ship as an apt package can be installed/removed here.
    ext_rows = [
        {"name": ext, "installed": ext in installed}
        for ext in php_catalog.AVAILABLE_EXTENSIONS
        if php_catalog.apt_package(ext, php_version) is not None
    ]
    flash = request.session.pop("flash", None)
    return templates.TemplateResponse(
        request, "whm/software.html",
        {"user": admin, "active": "software", "flash": flash,
         "php_version": php_version, "php_versions": php_catalog.PHP_VERSIONS,
         "ext_rows": ext_rows,
         "node_runtime": provider.node_installed_version(),
         "node_versions": config.NODE_VERSIONS},
    )


@router.post("/software/php/install")
async def software_php_install(
    request: Request, extension: str = Form(...), php_version: str = Form(_SOFTWARE_PHP),
    admin: User = Depends(require_admin), db: Session = Depends(get_db),
):
    return await _software_php(request, extension, php_version, install=True)


@router.post("/software/php/uninstall")
async def software_php_uninstall(
    request: Request, extension: str = Form(...), php_version: str = Form(_SOFTWARE_PHP),
    admin: User = Depends(require_admin), db: Session = Depends(get_db),
):
    return await _software_php(request, extension, php_version, install=False)


async def _software_php(request: Request, extension: str, php_version: str, install: bool):
    extension = (extension or "").strip()
    if php_version not in php_catalog.PHP_VERSIONS:
        _flash(request, "❌ Unsupported PHP version.")
        return RedirectResponse("/whm/software", status_code=303)
    if extension not in php_catalog.AVAILABLE_EXTENSIONS:
        _flash(request, "❌ Unknown extension.")
        return RedirectResponse("/whm/software", status_code=303)
    if php_catalog.apt_package(extension, php_version) is None:
        _flash(request, f"❌ {extension} is not installable via a package.")
        return RedirectResponse("/whm/software", status_code=303)
    provider = get_provider()
    fn = provider.install_extension if install else provider.uninstall_extension
    ok, message = await run_in_threadpool(fn, extension, php_version)
    _flash(request, ("✅ " if ok else "❌ ") + message)
    return RedirectResponse("/whm/software", status_code=303)


@router.post("/software/node/install")
async def software_node_install(
    request: Request, version: str = Form(...),
    admin: User = Depends(require_admin), db: Session = Depends(get_db),
):
    version = (version or "").strip()
    if version not in config.NODE_VERSIONS:
        _flash(request, "❌ Unsupported Node.js version.")
        return RedirectResponse("/whm/software", status_code=303)
    ok, message = await run_in_threadpool(get_provider().install_node, version)
    _flash(request, ("✅ " if ok else "❌ ") + message)
    return RedirectResponse("/whm/software", status_code=303)


# --- Service Manager (systemctl — admin only) -----------------------------
# Start/stop/restart the core system services. Runs systemctl as root, so it's
# admin-only (never a reseller). The client only ever sends a service `key` from
# the fixed catalog (config.MANAGED_SERVICES) — the provider maps it to the real
# unit, so a request can never target an arbitrary unit.
@router.get("/services")
def services(request: Request, admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    rows = get_provider().list_services()
    flash = request.session.pop("flash", None)
    return templates.TemplateResponse(
        request, "whm/services.html",
        {"user": admin, "active": "services", "flash": flash, "services": rows,
         "installable": list(config.SERVICE_PACKAGES),
         "web_fronting": web_fronting_enabled(),
         "redis_tuning": redis_tuning(),
         "redis_policies": config.REDIS_EVICTION_POLICIES},
    )


@router.post("/services/control")
async def services_control(
    request: Request, service: str = Form(...), action: str = Form(...),
    admin: User = Depends(require_admin), db: Session = Depends(get_db),
):
    if action not in ("start", "stop", "restart"):
        _flash(request, "❌ Unknown action.")
        return RedirectResponse("/whm/services", status_code=303)
    ok, message = await run_in_threadpool(get_provider().control_service, service, action)
    _flash(request, ("✅ " if ok else "❌ ") + message)
    return RedirectResponse("/whm/services", status_code=303)


# Install a service on demand (apt-get as root). Only catalog keys that are in
# config.SERVICE_PACKAGES are installable — anything else is rejected before apt
# runs, so a client can never install an arbitrary package. Admin-only.
@router.post("/services/install")
async def services_install(
    request: Request, key: str = Form(...),
    admin: User = Depends(require_admin), db: Session = Depends(get_db),
):
    if key not in config.SERVICE_PACKAGES:
        _flash(request, "❌ That service can't be installed from here.")
        return RedirectResponse("/whm/services", status_code=303)
    ok, message = await run_in_threadpool(get_provider().install_service, key)
    _flash(request, ("✅ " if ok else "❌ ") + message)
    return RedirectResponse("/whm/services", status_code=303)


def _all_site_vhosts(db: Session) -> list[SiteVhost]:
    """Snapshot every hosted vhost as DB-free descriptors for set_web_fronting.

    The provider never touches the ORM, so the router hands it exactly what each
    vhost generator needs. Node-app domains are flagged is_node (they proxy to a
    long-running process and must not front through Varnish — it would break
    their WebSocket upgrades), so the provider leaves them direct."""
    node_ids = set(db.scalars(select(NodeApp.domain_id)).all())
    sites: list[SiteVhost] = []
    for d in db.scalars(select(Domain)).all():
        user = d.owner.system_user or d.owner.username
        has_ssl = d.certificate is not None
        sites.append(SiteVhost(
            name=d.name, docroot=d.docroot, php_version=d.php_version,
            system_user=user, has_ssl=has_ssl, force_https=bool(d.force_https),
            extra_names=f" www.{d.name}", is_node=d.id in node_ids,
        ))
        for s in d.subdomains:
            sub_ssl = s.certificate is not None
            sites.append(SiteVhost(
                name=s.fqdn, docroot=s.docroot, php_version=s.php_version,
                system_user=user, has_ssl=sub_ssl, force_https=sub_ssl,
                extra_names="", is_node=False,
            ))
    return sites


# Turn the Varnish web-fronting sandwich on or off for every hosted site. Admin
# only (rewrites all vhosts + restarts Varnish as root). Refuses to switch ON
# unless Varnish is installed and running, so we never front onto a dead cache.
@router.post("/services/varnish-fronting")
async def services_varnish_fronting(
    request: Request, enabled: str = Form(""),
    admin: User = Depends(require_admin), db: Session = Depends(get_db),
):
    want_on = enabled.lower() in ("1", "true", "on", "yes")
    if want_on:
        svcs = {s["key"]: s for s in get_provider().list_services()}
        v = svcs.get("varnish")
        if not v or not v.get("available"):
            _flash(request, "❌ Install Varnish first, then enable web fronting.")
            return RedirectResponse("/whm/services", status_code=303)
        if v.get("status") != "running":
            _flash(request, "❌ Start Varnish first — it must be running before fronting is enabled.")
            return RedirectResponse("/whm/services", status_code=303)
    sites = _all_site_vhosts(db)
    ok, message = await run_in_threadpool(get_provider().set_web_fronting, want_on, sites)
    _flash(request, ("✅ " if ok else "❌ ") + message)
    return RedirectResponse("/whm/services", status_code=303)


# Cap Redis's memory and pick its eviction policy (a systemd drop-in + restart,
# as root). Admin only. maxmemory_mb is an int (non-int → 422) and clamped to a
# sane range; policy is checked against the allowlist — so neither can inject a
# raw redis.conf/systemd directive. Refuses unless Redis is installed + running.
@router.post("/services/redis-tune")
async def services_redis_tune(
    request: Request, maxmemory_mb: int = Form(...), policy: str = Form(...),
    admin: User = Depends(require_admin), db: Session = Depends(get_db),
):
    svcs = {s["key"]: s for s in get_provider().list_services()}
    r = svcs.get("redis")
    if not r or not r.get("available"):
        _flash(request, "❌ Install Redis first, then tune it.")
        return RedirectResponse("/whm/services", status_code=303)
    if r.get("status") != "running":
        _flash(request, "❌ Start Redis first — it must be running before it can be tuned.")
        return RedirectResponse("/whm/services", status_code=303)
    if policy not in config.REDIS_EVICTION_POLICIES:
        _flash(request, "❌ Unknown eviction policy.")
        return RedirectResponse("/whm/services", status_code=303)
    maxmemory_mb = max(config.REDIS_MAXMEMORY_MIN_MB,
                       min(config.REDIS_MAXMEMORY_MAX_MB, maxmemory_mb))
    ok, message = await run_in_threadpool(get_provider().tune_redis, maxmemory_mb, policy)
    _flash(request, ("✅ " if ok else "❌ ") + message)
    return RedirectResponse("/whm/services", status_code=303)


# Read-only `systemctl status` for one service. GET (no state change), admin-only.
# The key is a catalog id; the provider maps it to a real unit, so an arbitrary
# unit can never be targeted here either.
@router.get("/services/status/{key}")
async def service_status(
    request: Request, key: str,
    admin: User = Depends(require_admin), db: Session = Depends(get_db),
):
    ok, text = await run_in_threadpool(get_provider().service_status, key)
    label = config.SERVICE_LABELS.get(key, "Unknown service")
    return templates.TemplateResponse(
        request, "whm/service_status.html",
        {"user": admin, "active": "services", "label": label,
         "ok": ok, "text": text},
    )


# --- Panel Update (self-update — admin only) ------------------------------
# Update the panel software itself: sync to the latest code, run migrations, and
# restart — all hosted data preserved. Like cPanel/WHM's "Upgrade to Latest
# Version". Admin-only (shells out as root, restarts the service). The actual
# work runs detached in the provider so the restart can't kill the request.
@router.get("/panel-update")
async def panel_update(request: Request, admin: User = Depends(require_admin),
                       db: Session = Depends(get_db)):
    provider = get_provider()
    version = await run_in_threadpool(provider.panel_version)
    check = await run_in_threadpool(provider.check_panel_update)
    log = await run_in_threadpool(provider.panel_update_log, 100)
    flash = request.session.pop("flash", None)
    return templates.TemplateResponse(
        request, "whm/panel_update.html",
        {"user": admin, "active": "panel-update", "flash": flash,
         "version": version, "check": check, "log": log,
         "branch": config.PANEL_REPO_BRANCH},
    )


@router.post("/panel-update/check")
async def panel_update_check(request: Request, admin: User = Depends(require_admin),
                             db: Session = Depends(get_db)):
    check = await run_in_threadpool(get_provider().check_panel_update)
    _flash(request, ("🆕 " if check["available"] else "✅ ") + check["message"])
    return RedirectResponse("/whm/panel-update", status_code=303)


@router.post("/panel-update/run")
async def panel_update_run(request: Request, admin: User = Depends(require_admin),
                           db: Session = Depends(get_db)):
    ok, message = await run_in_threadpool(get_provider().update_panel)
    _flash(request, ("✅ " if ok else "❌ ") + message)
    return RedirectResponse("/whm/panel-update", status_code=303)
