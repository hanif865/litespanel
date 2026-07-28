"""Application entrypoint.

Run with:  uvicorn app.main:app --host 0.0.0.0 --port 8000
On a VPS, keep it to a single worker for the smallest footprint.
"""
from __future__ import annotations

from fastapi import FastAPI, Request
from fastapi.exceptions import HTTPException
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.sessions import SessionMiddleware

from . import config
from .db import SessionLocal, init_db
from .models import User
from .security import hash_password
from .web import TEMPLATES_DIR, templates
from .routers import (
    auth, autoresponders, backups, cron, dashboard, databases, dbconsole, dbwizard,
    dns, domains, email, files, forwarders, packages, php, ssl, subdomains, users,
)

app = FastAPI(title=config.APP_NAME, docs_url=None, redoc_url=None)

app.add_middleware(SessionMiddleware, secret_key=config.SECRET_KEY, session_cookie=config.SESSION_COOKIE)

# Static assets (CSS). Directory is created by init_db()/ensure_dirs isn't
# responsible for it, so ensure it exists here.
STATIC_DIR = TEMPLATES_DIR.parent / "static"
STATIC_DIR.mkdir(parents=True, exist_ok=True)
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

app.include_router(auth.router)
app.include_router(dashboard.router)
app.include_router(domains.router)
app.include_router(subdomains.router)
app.include_router(dns.router)
app.include_router(email.router)
app.include_router(forwarders.router)
app.include_router(autoresponders.router)
app.include_router(files.router)
app.include_router(databases.router)
app.include_router(dbwizard.router)
app.include_router(dbconsole.router)
app.include_router(php.router)
app.include_router(cron.router)
app.include_router(ssl.router)
app.include_router(backups.router)
app.include_router(packages.router)
app.include_router(users.router)


@app.on_event("startup")
def _startup() -> None:
    init_db()
    _bootstrap_admin()


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


@app.get("/healthz")
def healthz():
    return {"status": "ok", "provider": config.PROVIDER}
