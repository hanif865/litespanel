"""Cron job management.

Jobs are stored in the panel DB (source of truth) and synced to the system
crontab via the provider on every change.
"""
from __future__ import annotations

import re

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import RedirectResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..db import get_db
from ..models import CronJob, User
from ..providers import get_provider
from ..security import current_user
from ..web import templates

router = APIRouter(prefix="/cron", tags=["cron"])

# Each cron field: * , - / and digits (a light sanity check, not full RFC).
_FIELD_RE = re.compile(r"^[\d\*,\-/]{1,32}$")


def _flash(request: Request, message: str) -> None:
    request.session["flash"] = message


def _sync(db: Session) -> None:
    """Push all stored jobs to the system crontab via the provider."""
    jobs = db.scalars(select(CronJob).order_by(CronJob.id)).all()
    lines = [f"{j.schedule} {j.command}" for j in jobs]
    get_provider().sync_cron(lines)


@router.get("")
def list_cron(request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)):
    jobs = db.scalars(
        select(CronJob).where(CronJob.owner_id == user.id).order_by(CronJob.created_at.desc())
    ).all()
    flash = request.session.pop("flash", None)
    return templates.TemplateResponse(
        request, "cron.html", {"user": user, "jobs": jobs, "active": "cron", "flash": flash}
    )


@router.post("/create")
def create_cron(
    request: Request,
    minute: str = Form("*"),
    hour: str = Form("*"),
    day: str = Form("*"),
    month: str = Form("*"),
    weekday: str = Form("*"),
    command: str = Form(...),
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    fields = {"minute": minute, "hour": hour, "day": day, "month": month, "weekday": weekday}
    for label, val in fields.items():
        if not _FIELD_RE.match(val.strip()):
            _flash(request, f"❌ Invalid value in '{label}' field.")
            return RedirectResponse("/cron", status_code=303)
    if not command.strip():
        _flash(request, "❌ Command is required.")
        return RedirectResponse("/cron", status_code=303)

    db.add(CronJob(owner_id=user.id, command=command.strip(),
                   **{k: v.strip() for k, v in fields.items()}))
    db.commit()
    _sync(db)
    _flash(request, "✅ Cron job added.")
    return RedirectResponse("/cron", status_code=303)


@router.post("/{job_id}/delete")
def delete_cron(
    request: Request,
    job_id: int,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    job = db.get(CronJob, job_id)
    if job is None or job.owner_id != user.id:
        _flash(request, "❌ Job not found.")
        return RedirectResponse("/cron", status_code=303)
    db.delete(job)
    db.commit()
    _sync(db)
    _flash(request, "🗑️ Cron job removed.")
    return RedirectResponse("/cron", status_code=303)
