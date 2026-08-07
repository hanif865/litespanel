"""Error log — admin-only view of persisted unhandled exceptions.

The catch-all in app/main.py writes an ErrorLog row for every unhandled server
error. This router lets an admin browse the newest ones (with full traceback)
and clear the table, so debugging a 500 no longer means SSHing in to read the
journal. Viewing errors is admin-only; a non-admin is bounced to the dashboard.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from fastapi.responses import RedirectResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..db import get_db
from ..models import ErrorLog, User
from ..security import current_user
from ..web import templates

router = APIRouter(prefix="/errors", tags=["errors"])


@router.get("")
def list_errors(
    request: Request,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    if user.role != "admin":
        request.session["flash"] = "❌ The error log is an admin-only feature."
        return RedirectResponse("/", status_code=303)

    errors = db.scalars(
        select(ErrorLog).order_by(ErrorLog.id.desc()).limit(200)
    ).all()
    flash = request.session.pop("flash", None)
    return templates.TemplateResponse(
        request,
        "errors.html",
        {"user": user, "is_admin": True, "errors": errors, "flash": flash, "active": "errors"},
    )


@router.post("/clear")
def clear_errors(
    request: Request,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    if user.role != "admin":
        request.session["flash"] = "❌ The error log is an admin-only feature."
        return RedirectResponse("/", status_code=303)

    deleted = db.query(ErrorLog).delete()
    db.commit()
    request.session["flash"] = f"🧹 Cleared {deleted} error log entr{'y' if deleted == 1 else 'ies'}."
    return RedirectResponse("/errors", status_code=303)
