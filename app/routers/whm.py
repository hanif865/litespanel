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

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import RedirectResponse
from starlette.concurrency import run_in_threadpool
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import config, php_catalog
from ..accounts import account_home, terminate_account
from ..db import get_db
from ..models import Domain, Package, User
from ..providers import get_provider
from ..routers.domains import _DOMAIN_RE
from ..routers.packages import _NAME_RE, visible_packages
from ..routers.users import _USERNAME_RE, _can_manage, _owned_package, _visible_users
from ..security import hash_password, require_admin, require_manager
from ..web import templates

router = APIRouter(prefix="/whm", tags=["whm"])


def _flash(request: Request, message: str) -> None:
    request.session["flash"] = message


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

    plan = f" on package '{pkg.name}'" if pkg else ""
    _flash(request, f"✅ {role.capitalize()} '{username}' created{plan} with primary domain {domain}.")
    return RedirectResponse("/whm/accounts", status_code=303)


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
