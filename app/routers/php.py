"""PHP Selector — per-account/per-domain PHP version, extensions and php.ini.

cPanel-style. The panel DB (PhpConfig rows) is the source of truth; the active
provider materializes the chosen extensions + php.ini directives to disk via
apply_php_config. Two scopes:
  * Account global — one profile per account (domain_id NULL), the default.
  * Per domain     — overrides the global profile for a single domain.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import RedirectResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import php_catalog
from ..db import get_db
from ..models import Domain, PhpConfig, User
from ..providers import get_provider
from ..security import current_user
from ..web import templates

router = APIRouter(prefix="/php", tags=["php"])

PHP_VERSIONS = php_catalog.PHP_VERSIONS


def _flash(request: Request, message: str) -> None:
    request.session["flash"] = message


def _account_user(user: User) -> str:
    return user.system_user or user.username


def _get_or_create_config(db: Session, user: User, domain: Domain | None) -> PhpConfig:
    """Fetch the PhpConfig row for a scope, creating it with defaults if absent."""
    domain_id = domain.id if domain else None
    cfg = db.scalar(
        select(PhpConfig).where(
            PhpConfig.owner_id == user.id,
            PhpConfig.domain_id == domain_id,
        )
    )
    if cfg is None:
        version = domain.php_version if domain else php_catalog.DEFAULT_PHP_VERSION
        cfg = PhpConfig(
            owner_id=user.id,
            domain_id=domain_id,
            php_version=version,
            extensions=php_catalog.default_extensions(),
            directives=php_catalog.default_directives(),
        )
        db.add(cfg)
        db.flush()
    return cfg


def _resolve_domain(db: Session, user: User, domain_id: int | None) -> Domain | None:
    """Validate an optional per-domain scope belongs to the user."""
    if not domain_id:
        return None
    domain = db.get(Domain, domain_id)
    if domain is None or domain.owner_id != user.id:
        return None
    return domain


def _apply(cfg: PhpConfig, user: User, domain: Domain | None) -> None:
    """Push the stored config to the provider (extensions + php.ini)."""
    get_provider().apply_php_config(
        _account_user(user),
        cfg.php_version,
        php_catalog.merged_extensions(cfg.extensions),
        php_catalog.merged_directives(cfg.directives),
        domain=domain.name if domain else None,
    )


@router.get("")
def php_selector(
    request: Request,
    domain_id: int | None = None,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    domains = db.scalars(
        select(Domain).where(Domain.owner_id == user.id).order_by(Domain.name)
    ).all()
    domain = _resolve_domain(db, user, domain_id)
    cfg = _get_or_create_config(db, user, domain)
    db.commit()

    flash = request.session.pop("flash", None)

    # Toggling an extension only records intent — it still has to be present as a
    # system package to actually load. Show which are installed, and (admins only)
    # offer 1-click install for the ones that ship as an apt package.
    installed = get_provider().list_installed_extensions(cfg.php_version)
    installable = {
        ext: php_catalog.apt_package(ext, cfg.php_version) is not None
        for ext in php_catalog.AVAILABLE_EXTENSIONS
    }
    return templates.TemplateResponse(
        request,
        "php.html",
        {
            "user": user,
            "domains": domains,
            "scope_domain": domain,
            "versions": PHP_VERSIONS,
            "extensions": php_catalog.AVAILABLE_EXTENSIONS,
            "ext_groups": php_catalog.grouped_extensions(),
            "directive_order": php_catalog.DIRECTIVE_ORDER,
            "ext_state": php_catalog.merged_extensions(cfg.extensions),
            "dir_state": php_catalog.merged_directives(cfg.directives),
            "current_version": cfg.php_version,
            "installed": installed,
            "installable": installable,
            "is_admin": user.role == "admin",
            "active": "php",
            "flash": flash,
        },
    )


def _redirect(domain: Domain | None) -> RedirectResponse:
    url = "/php" + (f"?domain_id={domain.id}" if domain else "")
    return RedirectResponse(url, status_code=303)


@router.post("/version")
def set_version(
    request: Request,
    php_version: str = Form(...),
    domain_id: int | None = Form(None),
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    if php_version not in PHP_VERSIONS:
        _flash(request, "❌ Unsupported PHP version.")
        return RedirectResponse("/php", status_code=303)
    domain = _resolve_domain(db, user, domain_id)
    cfg = _get_or_create_config(db, user, domain)
    cfg.php_version = php_version
    if domain is not None:
        domain.php_version = php_version
    _apply(cfg, user, domain)
    db.commit()
    scope = domain.name if domain else "account default"
    _flash(request, f"✅ {scope} now uses PHP {php_version}.")
    return _redirect(domain)


@router.post("/extensions")
async def set_extensions(
    request: Request,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    form = await request.form()
    domain_id = form.get("domain_id")
    domain = _resolve_domain(db, user, int(domain_id) if domain_id else None)
    cfg = _get_or_create_config(db, user, domain)
    # Checkboxes only post when checked; anything not present is disabled.
    checked = set(form.getlist("ext"))
    cfg.extensions = {name: (name in checked) for name in php_catalog.AVAILABLE_EXTENSIONS}
    _apply(cfg, user, domain)
    db.commit()
    _flash(request, "✅ PHP extensions updated.")
    return _redirect(domain)


@router.post("/directives")
async def set_directives(
    request: Request,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    form = await request.form()
    domain_id = form.get("domain_id")
    domain = _resolve_domain(db, user, int(domain_id) if domain_id else None)
    cfg = _get_or_create_config(db, user, domain)
    directives = {}
    for key in php_catalog.DIRECTIVE_ORDER:
        value = form.get(f"dir_{key}")
        if value is not None and value.strip() != "":
            directives[key] = value.strip()
    cfg.directives = directives
    _apply(cfg, user, domain)
    db.commit()
    _flash(request, "✅ php.ini options saved.")
    return _redirect(domain)


@router.post("/reset-extensions")
async def reset_extensions(
    request: Request,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    form = await request.form()
    domain_id = form.get("domain_id")
    domain = _resolve_domain(db, user, int(domain_id) if domain_id else None)
    cfg = _get_or_create_config(db, user, domain)
    cfg.extensions = php_catalog.default_extensions()
    _apply(cfg, user, domain)
    db.commit()
    _flash(request, "↩️ PHP extensions reset to default.")
    return _redirect(domain)


@router.post("/install")
async def install_extension(
    request: Request,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    """Install a PHP extension system package. Admin only (shells out as root)."""
    form = await request.form()
    domain_id = form.get("domain_id")
    domain = _resolve_domain(db, user, int(domain_id) if domain_id else None)
    extension = (form.get("extension") or "").strip()

    if user.role != "admin":
        _flash(request, "❌ Only an admin can install PHP extensions.")
        return _redirect(domain)
    if extension not in php_catalog.AVAILABLE_EXTENSIONS:
        _flash(request, "❌ Unknown extension.")
        return _redirect(domain)

    cfg = _get_or_create_config(db, user, domain)
    if php_catalog.apt_package(extension, cfg.php_version) is None:
        _flash(request, f"❌ {extension} is not installable via a package.")
        return _redirect(domain)

    ok, message = get_provider().install_extension(extension, cfg.php_version)
    _flash(request, ("✅ " if ok else "❌ ") + message)
    return _redirect(domain)


@router.post("/uninstall")
async def uninstall_extension(
    request: Request,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    """Remove a PHP extension system package. Admin only (shells out as root)."""
    form = await request.form()
    domain_id = form.get("domain_id")
    domain = _resolve_domain(db, user, int(domain_id) if domain_id else None)
    extension = (form.get("extension") or "").strip()

    if user.role != "admin":
        _flash(request, "❌ Only an admin can remove PHP extensions.")
        return _redirect(domain)
    if extension not in php_catalog.AVAILABLE_EXTENSIONS:
        _flash(request, "❌ Unknown extension.")
        return _redirect(domain)

    cfg = _get_or_create_config(db, user, domain)
    if php_catalog.apt_package(extension, cfg.php_version) is None:
        _flash(request, f"❌ {extension} cannot be removed (built-in or not a package).")
        return _redirect(domain)

    ok, message = get_provider().uninstall_extension(extension, cfg.php_version)
    _flash(request, ("✅ " if ok else "❌ ") + message)
    return _redirect(domain)
