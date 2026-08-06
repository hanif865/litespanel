"""Node.js apps — admin-only runtime install + per-domain reverse-proxy apps.

Node.js support is an admin feature: only an admin can install the runtime or
deploy an app. Deploying an app on a domain rewrites that domain's nginx vhost
to reverse-proxy to a systemd-managed Node process (see the provider layer).
The panel DB (NodeApp rows) is the source of truth; the provider materializes
the systemd unit + nginx config from it.
"""
from __future__ import annotations

import re

from fastapi import APIRouter, Depends, Request
from fastapi.responses import PlainTextResponse, RedirectResponse
from starlette.concurrency import run_in_threadpool
from sqlalchemy import select
from sqlalchemy.orm import Session

from pathlib import Path

from .. import config
from ..db import get_db
from ..models import Domain, NodeApp, User
from ..providers import get_provider
from ..security import current_user
from ..web import templates

router = APIRouter(prefix="/node", tags=["node"])

NODE_VERSIONS = config.NODE_VERSIONS
_ENTRY_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/ -]{0,254}$")
# App root: a relative subdir under docroot; no leading slash, no traversal.
_APP_ROOT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,254}$")
# npm script name accepted for a custom start command.
_START_CMD_RE = re.compile(r"^[A-Za-z0-9._:-]{1,64}$")


def _clean_app_root(raw: str) -> str | None:
    """Validate an optional relative app-root subdir. Returns "" for empty,
    the cleaned value if safe, or None if invalid."""
    root = (raw or "").strip().strip("/")
    if not root:
        return ""
    if ".." in root.split("/") or not _APP_ROOT_RE.match(root):
        return None
    return root


def _flash(request: Request, message: str) -> None:
    request.session["flash"] = message


def _account_user(user: User) -> str:
    return user.system_user or user.username


def _redirect() -> RedirectResponse:
    return RedirectResponse("/node", status_code=303)


def _slug(domain: str) -> str:
    """Turn a domain into a safe systemd-unit slug (example.com -> example-com)."""
    slug = re.sub(r"[^a-z0-9]+", "-", domain.lower()).strip("-")
    return slug or "app"


def _next_port(db: Session) -> int:
    """First free port at/above the configured base, avoiding used ones."""
    used = set(db.scalars(select(NodeApp.port)).all())
    port = config.NODE_PORT_BASE
    while port in used:
        port += 1
    return port


@router.get("")
def node_home(
    request: Request,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    if user.role != "admin":
        _flash(request, "❌ Node.js is an admin-only feature.")
        return RedirectResponse("/", status_code=303)

    flash = request.session.pop("flash", None)
    provider = get_provider()

    apps = db.scalars(
        select(NodeApp).where(NodeApp.owner_id == user.id).order_by(NodeApp.name)
    ).all()
    app_rows = [{"app": a, "status": provider.node_app_status(a.name)} for a in apps]

    used_domain_ids = {a.domain_id for a in apps}
    available = db.scalars(
        select(Domain)
        .where(Domain.owner_id == user.id, Domain.id.notin_(used_domain_ids or {0}))
        .order_by(Domain.name)
    ).all()

    return templates.TemplateResponse(
        request,
        "node.html",
        {
            "user": user,
            "is_admin": True,
            "runtime": provider.node_installed_version(),
            "node_versions": NODE_VERSIONS,
            "apps": app_rows,
            "available_domains": available,
            "suggested_port": _next_port(db),
            "active": "node",
            "flash": flash,
        },
    )


@router.post("/deploy")
async def deploy(
    request: Request,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    if user.role != "admin":
        _flash(request, "❌ Only an admin can deploy Node.js apps.")
        return _redirect()

    form = await request.form()
    domain_id = form.get("domain_id")
    entrypoint = (form.get("entrypoint") or "server.js").strip()
    node_version = (form.get("node_version") or NODE_VERSIONS[0]).strip()
    port_raw = (form.get("port") or "").strip()
    start_command = (form.get("start_command") or "").strip()
    env_vars = (form.get("env_vars") or "").strip()

    domain = db.get(Domain, int(domain_id)) if domain_id else None
    if domain is None or domain.owner_id != user.id:
        _flash(request, "❌ Unknown domain.")
        return _redirect()
    if db.scalar(select(NodeApp).where(NodeApp.domain_id == domain.id)):
        _flash(request, f"❌ {domain.name} already runs a Node.js app.")
        return _redirect()
    if node_version not in NODE_VERSIONS:
        _flash(request, "❌ Unsupported Node.js version.")
        return _redirect()
    if not _ENTRY_RE.match(entrypoint):
        _flash(request, "❌ Invalid entrypoint file name.")
        return _redirect()
    app_root = _clean_app_root(form.get("app_root"))
    if app_root is None:
        _flash(request, "❌ App root must be a relative path (no leading / or '..').")
        return _redirect()
    if start_command and not _START_CMD_RE.match(start_command):
        _flash(request, "❌ Start command must be a valid npm script name.")
        return _redirect()
    try:
        port = int(port_raw) if port_raw else _next_port(db)
    except ValueError:
        _flash(request, "❌ Port must be a number.")
        return _redirect()
    if not (1024 <= port <= 65535):
        _flash(request, "❌ Port must be between 1024 and 65535.")
        return _redirect()
    if db.scalar(select(NodeApp).where(NodeApp.port == port)):
        _flash(request, f"❌ Port {port} is already in use by another app.")
        return _redirect()

    name = _slug(domain.name)
    app_dir = domain.docroot

    node_app = NodeApp(
        owner_id=user.id,
        domain_id=domain.id,
        name=name,
        port=port,
        node_version=node_version,
        entrypoint=entrypoint,
        app_dir=app_dir,
        app_root=app_root,
        start_command=start_command,
        env_vars=env_vars,
        active=True,
    )
    db.add(node_app)
    db.flush()

    provider = get_provider()
    ok, message = await run_in_threadpool(
        provider.deploy_node_app,
        name, domain.name, Path(app_dir), port, entrypoint,
        _account_user(user), node_version, start_command, env_vars, app_root,
    )
    node_app.active = ok
    db.commit()

    # Install dependencies so the project can actually run. Keep the app row
    # even if install fails — the admin can retry from the apps table.
    if ok:
        i_ok, i_msg = await run_in_threadpool(
            provider.npm_install, node_app, _account_user(user)
        )
        message += "\n" + ("✅ " if i_ok else "⚠️ ") + i_msg
    _flash(request, ("✅ " if ok else "⚠️ ") + message)
    return _redirect()


@router.post("/control")
async def control(
    request: Request,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    if user.role != "admin":
        _flash(request, "❌ Only an admin can control Node.js apps.")
        return _redirect()
    form = await request.form()
    app_id = form.get("app_id")
    action = (form.get("action") or "").strip()
    app = db.get(NodeApp, int(app_id)) if app_id else None
    if app is None or app.owner_id != user.id:
        _flash(request, "❌ Unknown app.")
        return _redirect()
    ok, message = await run_in_threadpool(get_provider().control_node_app, app.name, action)
    if ok:
        app.active = action != "stop"
        db.commit()
    _flash(request, ("✅ " if ok else "❌ ") + message)
    return _redirect()


@router.post("/remove")
async def remove(
    request: Request,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    if user.role != "admin":
        _flash(request, "❌ Only an admin can remove Node.js apps.")
        return _redirect()
    form = await request.form()
    app_id = form.get("app_id")
    app = db.get(NodeApp, int(app_id)) if app_id else None
    if app is None or app.owner_id != user.id:
        _flash(request, "❌ Unknown app.")
        return _redirect()

    domain = db.get(Domain, app.domain_id)
    provider = get_provider()
    await run_in_threadpool(
        provider.remove_node_app, app.name, domain.name if domain else app.name
    )
    # Restore the normal PHP vhost so the domain keeps serving after Node is off.
    if domain is not None:
        await run_in_threadpool(
            provider.create_site, domain.name, Path(domain.docroot),
            domain.php_version, _account_user(user),
        )
        await run_in_threadpool(provider.reload_web)
    db.delete(app)
    db.commit()
    _flash(request, f"🗑️ Node.js app removed; {domain.name if domain else 'domain'} restored to PHP.")
    return _redirect()


@router.post("/npm-install")
async def npm_install(
    request: Request,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    if user.role != "admin":
        _flash(request, "❌ Only an admin can run npm install.")
        return _redirect()
    form = await request.form()
    app_id = form.get("app_id")
    app = db.get(NodeApp, int(app_id)) if app_id else None
    if app is None or app.owner_id != user.id:
        _flash(request, "❌ Unknown app.")
        return _redirect()
    ok, message = await run_in_threadpool(
        get_provider().npm_install, app, _account_user(user)
    )
    _flash(request, ("✅ " if ok else "❌ ") + message)
    return _redirect()


@router.get("/logs/{app_id}")
def logs(
    app_id: int,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    if user.role != "admin":
        return PlainTextResponse("Node.js is an admin-only feature.", status_code=403)
    app = db.get(NodeApp, app_id)
    if app is None or app.owner_id != user.id:
        return PlainTextResponse("Unknown app.", status_code=404)
    text = get_provider().node_app_logs(app.name, 200)
    return PlainTextResponse(text or "(no logs)")


@router.post("/update-env")
async def update_env(
    request: Request,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    if user.role != "admin":
        _flash(request, "❌ Only an admin can update app environment.")
        return _redirect()
    form = await request.form()
    app_id = form.get("app_id")
    app = db.get(NodeApp, int(app_id)) if app_id else None
    if app is None or app.owner_id != user.id:
        _flash(request, "❌ Unknown app.")
        return _redirect()

    app.env_vars = (form.get("env_vars") or "").strip()
    db.flush()
    domain = db.get(Domain, app.domain_id)
    ok, message = await run_in_threadpool(
        get_provider().deploy_node_app,
        app.name, domain.name if domain else app.name, Path(app.app_dir),
        app.port, app.entrypoint, _account_user(user), app.node_version,
        app.start_command, app.env_vars, app.app_root,
    )
    db.commit()
    _flash(request, ("✅ Environment updated. " if ok else "⚠️ ") + message)
    return _redirect()
