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
from ..models import Domain, NodeApp, PhpConfig, Subdomain, User
from ..providers import get_provider
from ..providers.base import SiteVhost
from ..security import current_user
from ..web import templates

router = APIRouter(prefix="/php", tags=["php"])

PHP_VERSIONS = php_catalog.PHP_VERSIONS


def _flash(request: Request, message: str) -> None:
    request.session["flash"] = message


def _account_user(user: User) -> str:
    return user.system_user or user.username


# A PHP Selector scope is one of: the account global profile, a single domain,
# or a single subdomain. The UI encodes it in one `scope` field:
#   ""        -> account global
#   "d<id>"   -> domain <id>
#   "s<id>"   -> subdomain <id>
def _scope_value(domain: Domain | None, subdomain: Subdomain | None) -> str:
    if subdomain is not None:
        return f"s{subdomain.id}"
    if domain is not None:
        return f"d{domain.id}"
    return ""


def _parse_scope(db: Session, user: User, scope: str | None
                 ) -> tuple[Domain | None, Subdomain | None]:
    """Resolve a `scope` string to (domain, subdomain), validating ownership.
    Anything unrecognised or not owned falls back to the account-global scope."""
    scope = (scope or "").strip()
    if scope.startswith("d") and scope[1:].isdigit():
        domain = db.get(Domain, int(scope[1:]))
        if domain is not None and domain.owner_id == user.id:
            return domain, None
    elif scope.startswith("s") and scope[1:].isdigit():
        sub = db.get(Subdomain, int(scope[1:]))
        if sub is not None and sub.parent.owner_id == user.id:
            return None, sub
    return None, None


def _get_or_create_config(db: Session, user: User,
                          domain: Domain | None, subdomain: Subdomain | None) -> PhpConfig:
    """Fetch the PhpConfig row for a scope, creating it with defaults if absent."""
    domain_id = domain.id if domain else None
    subdomain_id = subdomain.id if subdomain else None
    cfg = db.scalar(
        select(PhpConfig).where(
            PhpConfig.owner_id == user.id,
            PhpConfig.domain_id == domain_id,
            PhpConfig.subdomain_id == subdomain_id,
        )
    )
    if cfg is None:
        if subdomain is not None:
            version = subdomain.php_version
        elif domain is not None:
            version = domain.php_version
        else:
            version = php_catalog.DEFAULT_PHP_VERSION
        cfg = PhpConfig(
            owner_id=user.id,
            domain_id=domain_id,
            subdomain_id=subdomain_id,
            php_version=version,
            extensions=php_catalog.default_extensions(),
            directives=php_catalog.default_directives(),
        )
        db.add(cfg)
        db.flush()
    return cfg


def _scope_label(domain: Domain | None, subdomain: Subdomain | None) -> str | None:
    if subdomain is not None:
        return subdomain.fqdn
    if domain is not None:
        return domain.name
    return None


def _apply(cfg: PhpConfig, user: User,
           domain: Domain | None, subdomain: Subdomain | None) -> None:
    """Push the stored config to the provider (FPM pool for this version +
    extensions + php.ini)."""
    get_provider().apply_php_config(
        _account_user(user),
        cfg.php_version,
        php_catalog.merged_extensions(cfg.extensions),
        php_catalog.merged_directives(cfg.directives),
        domain=_scope_label(domain, subdomain),
    )


def _apply_safe(cfg: PhpConfig, user: User,
                domain: Domain | None, subdomain: Subdomain | None) -> str | None:
    """Materialize the config to the provider, but never let a failing shell-out
    (systemctl/nginx) bubble up as a 500. Returns an error message on failure so
    the caller can flash it — the DB intent is still saved and can be retried."""
    try:
        _apply(cfg, user, domain, subdomain)
        return None
    except Exception as exc:  # noqa: BLE001 — surface the reason, don't 500.
        return str(exc)


def _rebuild_vhost(db: Session, user: User,
                   domain: Domain | None, subdomain: Subdomain | None) -> str | None:
    """After a version change, repoint the affected site's vhost at the new FPM
    socket (SSL/mode-safe). Returns an error message on failure, else None. No-op
    for the account-global scope (no single site) and for Node.js domains (they
    reverse-proxy to a process, not PHP-FPM)."""
    try:
        account = _account_user(user)
        if subdomain is not None:
            has_ssl = subdomain.certificate is not None
            site = SiteVhost(
                name=subdomain.fqdn, docroot=subdomain.docroot, php_version=subdomain.php_version,
                system_user=account, has_ssl=has_ssl, force_https=has_ssl,
                extra_names="", is_node=False,
            )
        elif domain is not None:
            is_node = db.scalar(
                select(NodeApp.id).where(NodeApp.domain_id == domain.id)
            ) is not None
            if is_node:
                return None
            site = SiteVhost(
                name=domain.name, docroot=domain.docroot, php_version=domain.php_version,
                system_user=account, has_ssl=domain.certificate is not None,
                force_https=bool(domain.force_https), extra_names=f" www.{domain.name}",
                is_node=False,
            )
        else:
            return None
        ok, message = get_provider().rebuild_site_vhost(site)
        return None if ok else message
    except Exception as exc:  # noqa: BLE001 — never 500 on a vhost rebuild.
        return str(exc)


@router.get("")
def php_selector(
    request: Request,
    scope: str | None = None,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    domains = db.scalars(
        select(Domain).where(Domain.owner_id == user.id).order_by(Domain.name)
    ).all()
    # Subdomains the user owns (through their parent domains), for the scope picker.
    subdomains = [s for d in domains for s in d.subdomains]
    subdomains.sort(key=lambda s: s.fqdn)
    domain, subdomain = _parse_scope(db, user, scope)
    cfg = _get_or_create_config(db, user, domain, subdomain)
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
    # Which PHP versions can actually be selected (FPM installed on the host).
    installed_versions = [v for v in PHP_VERSIONS if get_provider().php_fpm_installed(v)]
    return templates.TemplateResponse(
        request,
        "php.html",
        {
            "user": user,
            "domains": domains,
            "subdomains": subdomains,
            "scope_domain": domain,
            "scope_subdomain": subdomain,
            "scope_value": _scope_value(domain, subdomain),
            "versions": PHP_VERSIONS,
            "installed_versions": installed_versions,
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


def _redirect(domain: Domain | None, subdomain: Subdomain | None = None) -> RedirectResponse:
    value = _scope_value(domain, subdomain)
    url = "/php" + (f"?scope={value}" if value else "")
    return RedirectResponse(url, status_code=303)


@router.post("/version")
def set_version(
    request: Request,
    php_version: str = Form(...),
    scope: str | None = Form(None),
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    if php_version not in PHP_VERSIONS:
        _flash(request, "❌ Unsupported PHP version.")
        return RedirectResponse("/php", status_code=303)
    # The Selector lists every catalog version; only switch to one that's actually
    # installed, or reloading its (missing) PHP-FPM unit would fail.
    if not get_provider().php_fpm_installed(php_version):
        _flash(request, f"❌ PHP {php_version} isn't installed on the server. "
                        f"An admin can install it in WHM → Server Software first.")
        domain, subdomain = _parse_scope(db, user, scope)
        return _redirect(domain, subdomain)
    domain, subdomain = _parse_scope(db, user, scope)
    cfg = _get_or_create_config(db, user, domain, subdomain)
    cfg.php_version = php_version
    if subdomain is not None:
        subdomain.php_version = php_version
    elif domain is not None:
        domain.php_version = php_version
    # Materialize the FPM pool/extensions for the new version, then repoint the
    # affected site's vhost at that version's socket (SSL/mode-safe). Neither step
    # may 500 — any shell-out failure is surfaced as a flash instead.
    apply_err = _apply_safe(cfg, user, domain, subdomain)
    vhost_err = _rebuild_vhost(db, user, domain, subdomain)
    db.commit()
    label = _scope_label(domain, subdomain) or "account default"
    err = apply_err or vhost_err
    if err:
        _flash(request, f"⚠️ PHP {php_version} saved for {label}, but applying it failed: {err}")
    else:
        _flash(request, f"✅ {label} now uses PHP {php_version}.")
    return _redirect(domain, subdomain)


@router.post("/extensions")
async def set_extensions(
    request: Request,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    form = await request.form()
    domain, subdomain = _parse_scope(db, user, form.get("scope"))
    cfg = _get_or_create_config(db, user, domain, subdomain)
    # Checkboxes only post when checked; anything not present is disabled.
    checked = set(form.getlist("ext"))
    cfg.extensions = {name: (name in checked) for name in php_catalog.AVAILABLE_EXTENSIONS}
    err = _apply_safe(cfg, user, domain, subdomain)
    db.commit()
    _flash(request, f"⚠️ Extensions saved, but applying them failed: {err}" if err
           else "✅ PHP extensions updated.")
    return _redirect(domain, subdomain)


@router.post("/directives")
async def set_directives(
    request: Request,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    form = await request.form()
    domain, subdomain = _parse_scope(db, user, form.get("scope"))
    cfg = _get_or_create_config(db, user, domain, subdomain)
    directives = {}
    for key in php_catalog.DIRECTIVE_ORDER:
        value = form.get(f"dir_{key}")
        if value is not None and value.strip() != "":
            directives[key] = value.strip()
    # PHP sessions on Redis is a guided, per-account toggle — never a raw knob.
    # A shared Redis has no session isolation by default, so one account could read
    # another's session keys. Force the server-derived, per-account-prefixed DSN
    # (overriding whatever session.* the form posted) so isolation can't be bypassed.
    if form.get("sessions_redis"):
        directives["session.save_handler"] = "redis"
        directives["session.save_path"] = f"tcp://127.0.0.1:6379?prefix={_account_user(user)}:"
    else:
        directives.pop("session.save_handler", None)
        directives.pop("session.save_path", None)
    cfg.directives = directives
    err = _apply_safe(cfg, user, domain, subdomain)
    db.commit()
    _flash(request, f"⚠️ Options saved, but applying them failed: {err}" if err
           else "✅ php.ini options saved.")
    return _redirect(domain, subdomain)


@router.post("/reset-extensions")
async def reset_extensions(
    request: Request,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    form = await request.form()
    domain, subdomain = _parse_scope(db, user, form.get("scope"))
    cfg = _get_or_create_config(db, user, domain, subdomain)
    cfg.extensions = php_catalog.default_extensions()
    err = _apply_safe(cfg, user, domain, subdomain)
    db.commit()
    _flash(request, f"⚠️ Reset saved, but applying it failed: {err}" if err
           else "↩️ PHP extensions reset to default.")
    return _redirect(domain, subdomain)
