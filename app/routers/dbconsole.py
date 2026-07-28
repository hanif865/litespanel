"""Database Manager — a phpMyAdmin-style console.

- If PANEL_PHPMYADMIN_URL is configured, embeds the real phpMyAdmin (iframe).
- Otherwise uses the built-in SQL console. In demo mode each database is a
  real SQLite file, so browsing tables and running queries actually works.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import RedirectResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import config
from ..db import get_db
from ..models import Database, User
from ..providers import get_provider
from ..security import current_user
from ..web import templates

router = APIRouter(prefix="/phpmyadmin", tags=["dbmanager"])


def _render(request, user, db, selected=None, result=None, sql=""):
    databases = db.scalars(
        select(Database).where(Database.owner_id == user.id).order_by(Database.name)
    ).all()
    if selected is None and databases:
        selected = databases[0]
    tables = get_provider().db_tables(selected.name) if selected else []
    return templates.TemplateResponse(
        request,
        "dbmanager.html",
        {
            "user": user, "active": "phpmyadmin",
            "phpmyadmin_url": config.PHPMYADMIN_URL,
            "databases": databases, "selected": selected,
            "tables": tables, "result": result, "sql": sql,
            "flash": request.session.pop("flash", None),
        },
    )


@router.get("")
def index(
    request: Request,
    db_name: str | None = None,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    selected = None
    if db_name:
        selected = db.scalar(
            select(Database).where(Database.owner_id == user.id, Database.name == db_name)
        )
    return _render(request, user, db, selected=selected)


@router.post("/query")
def run_query(
    request: Request,
    db_name: str = Form(...),
    sql: str = Form(...),
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    # When real phpMyAdmin is wired up, the built-in console is disabled — use
    # phpMyAdmin (which authenticates as the database's own scoped MySQL user)
    # instead of this passthrough.
    if config.PHPMYADMIN_URL:
        from fastapi import HTTPException

        raise HTTPException(status_code=404, detail="Use phpMyAdmin.")
    selected = db.scalar(
        select(Database).where(Database.owner_id == user.id, Database.name == db_name)
    )
    if selected is None:
        request.session["flash"] = "❌ Database not found."
        return RedirectResponse("/phpmyadmin", status_code=303)
    result = get_provider().db_execute(selected.name, sql)
    return _render(request, user, db, selected=selected, result=result, sql=sql)
