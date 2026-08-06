"""Application entrypoint.

Run with:  uvicorn app.main:app --host 0.0.0.0 --port 8000
On a VPS, keep it to a single worker for the smallest footprint.
"""
from __future__ import annotations

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles
from starlette.exceptions import HTTPException
from starlette.middleware.sessions import SessionMiddleware

from . import config
from .db import SessionLocal, init_db
from .middleware import CSRFMiddleware, SecurityHeadersMiddleware
from .models import User
from .security import hash_password
from .web import TEMPLATES_DIR, templates
from .routers import (
    account, auth, autoresponders, backups, cron, dashboard, databases, dbconsole, dbwizard,
    disk_usage, dns, domains, email, files, firewall, forwarders, ftp, git, ip_blocker, logs,
    metrics, modsecurity, node,
    packages, pg_databases, php, ssl, subdomains, users, webdisk, wordpress,
)

app = FastAPI(title=config.APP_NAME, docs_url=None, redoc_url=None)

# Middleware order: the LAST added is the OUTERMOST. Session must be inner so
# the security layers wrap around it.
app.add_middleware(
    SessionMiddleware,
    secret_key=config.SECRET_KEY,
    session_cookie=config.SESSION_COOKIE,
    same_site="lax",              # blocks the cookie on cross-site requests (CSRF)
    https_only=config.HTTPS_ONLY,  # Secure flag once served over HTTPS
    max_age=60 * 60 * 12,          # 12h sessions
)
app.add_middleware(CSRFMiddleware)
app.add_middleware(SecurityHeadersMiddleware)

# Static assets (CSS). Directory is created by init_db()/ensure_dirs isn't
# responsible for it, so ensure it exists here.
STATIC_DIR = TEMPLATES_DIR.parent / "static"
STATIC_DIR.mkdir(parents=True, exist_ok=True)
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

app.include_router(auth.router)
app.include_router(account.router)
app.include_router(dashboard.router)
app.include_router(domains.router)
app.include_router(subdomains.router)
app.include_router(dns.router)
app.include_router(email.router)
app.include_router(forwarders.router)
app.include_router(autoresponders.router)
app.include_router(files.router)
app.include_router(disk_usage.router)
app.include_router(ftp.router)
app.include_router(webdisk.router)
app.include_router(git.router)
app.include_router(databases.router)
app.include_router(pg_databases.router)
app.include_router(dbwizard.router)
app.include_router(dbconsole.router)
app.include_router(php.router)
app.include_router(node.router)
app.include_router(cron.router)
app.include_router(wordpress.router)
app.include_router(ssl.router)
app.include_router(firewall.router)
app.include_router(ip_blocker.router)
app.include_router(modsecurity.router)
app.include_router(logs.router)
app.include_router(metrics.router)
app.include_router(backups.router)
app.include_router(packages.router)
app.include_router(users.router)


@app.on_event("startup")
def _startup() -> None:
    init_db()
    _bootstrap_admin()
    _security_warnings()


def _security_warnings() -> None:
    """Print loud warnings for insecure production configuration."""
    import logging

    log = logging.getLogger("litespanel.security")
    if config.PROVIDER == "linux":
        if config.DEFAULT_ADMIN_PASSWORD == "admin":
            log.warning("⚠️  Admin password is the default 'admin' — set PANEL_ADMIN_PASSWORD!")
        if not config.HTTPS_ONLY:
            log.warning("⚠️  PANEL_HTTPS is off — enable it once served over HTTPS for Secure cookies.")


def _bootstrap_admin() -> None:
    """Create the default admin on first run so the panel is usable."""
    with SessionLocal() as db:
        if db.query(User).count() == 0:
            db.add(User(
                username=config.DEFAULT_ADMIN_USER,
                password_hash=hash_password(config.DEFAULT_ADMIN_PASSWORD),
                is_admin=True, role="admin",
            ))
            db.commit()


@app.exception_handler(HTTPException)
async def auth_redirect(request: Request, exc: HTTPException):
    """Send un-authenticated browser requests to the login page instead of a
    raw 401 JSON body."""
    if exc.status_code == 401:
        return RedirectResponse("/login", status_code=303)
    return templates.TemplateResponse(
        request, "error.html", {"status": exc.status_code, "detail": exc.detail},
        status_code=exc.status_code,
    )


@app.exception_handler(RequestValidationError)
async def validation_error(request: Request, exc: RequestValidationError):
    """Turn a raw 422 JSON body into a friendly page naming the bad fields."""
    fields: list[str] = []
    for err in exc.errors():
        # loc is like ("body", "port") — take the last human-meaningful part.
        loc = [str(p) for p in err.get("loc", ()) if p not in ("body", "query", "path")]
        if loc:
            name = loc[-1].replace("_", " ")
            if name not in fields:
                fields.append(name)
    if fields:
        detail = "Please check these fields: " + ", ".join(fields) + "."
    else:
        detail = "Some of the submitted values were invalid. Please review the form."
    return templates.TemplateResponse(
        request, "error.html", {"status": 422, "detail": detail},
        status_code=422,
    )


@app.exception_handler(Exception)
async def unhandled_error(request: Request, exc: Exception):
    """Catch-all so an unexpected error never leaks a traceback or raw JSON.

    The full exception is logged server-side (visible via journalctl) while the
    browser only sees a clean, generic page.
    """
    import logging

    logging.getLogger("litespanel").exception(
        "Unhandled error on %s %s", request.method, request.url.path
    )
    return templates.TemplateResponse(
        request, "error.html",
        {"status": 500, "detail": "Something went wrong on our end. The issue has been logged."},
        status_code=500,
    )


@app.get("/healthz")
def healthz():
    return {"status": "ok", "provider": config.PROVIDER}
