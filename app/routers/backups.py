"""Account backups — archive sites + databases (+ dns/mail) into a zip.

Each user backs up their own account. The archive is a portable zip that can
be downloaded and later restored (or restored on another node).
"""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from fastapi import APIRouter, Depends, File, Form, Request, UploadFile
from fastapi.responses import FileResponse, RedirectResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import config
from ..db import get_db
from ..models import Backup, Database, Domain, User
from ..providers import get_provider
from ..security import current_user
from ..web import templates

router = APIRouter(prefix="/backups", tags=["backups"])


def _flash(request: Request, message: str) -> None:
    request.session["flash"] = message


@router.get("")
def list_backups(request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)):
    backups = db.scalars(
        select(Backup).where(Backup.owner_id == user.id).order_by(Backup.created_at.desc())
    ).all()
    flash = request.session.pop("flash", None)
    return templates.TemplateResponse(
        request, "backups.html", {"user": user, "backups": backups, "active": "backups", "flash": flash}
    )


@router.post("/create")
def create_backup(
    request: Request,
    note: str = Form(""),
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    # Pass the real on-disk site directory for each domain (docroot's parent),
    # so the backup archives the actual files wherever they live (/home/<user>).
    sites = [
        (d.name, str(Path(d.docroot).parent))
        for d in db.scalars(select(Domain).where(Domain.owner_id == user.id))
    ]
    databases = [d.name for d in db.scalars(select(Database).where(Database.owner_id == user.id))]

    ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    filename = f"backup-{user.username}-{ts}.zip"
    dest = config.BACKUPS_DIR / filename
    summary = get_provider().create_backup(dest, sites, databases)

    db.add(Backup(owner_id=user.id, filename=filename,
                  size_bytes=summary["size_bytes"], note=note.strip()[:255]))
    db.commit()
    _flash(request, f"✅ Backup created ({len(summary['items'])} items).")
    return RedirectResponse("/backups", status_code=303)


@router.get("/{backup_id}/download")
def download_backup(
    backup_id: int,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    from fastapi import HTTPException

    backup = db.get(Backup, backup_id)
    if backup is None or backup.owner_id != user.id:
        raise HTTPException(status_code=404, detail="Backup not found.")
    path = config.BACKUPS_DIR / backup.filename
    if not path.is_file():
        raise HTTPException(status_code=404, detail="Backup file missing.")
    return FileResponse(path, filename=backup.filename, media_type="application/zip")


@router.post("/{backup_id}/delete")
def delete_backup(
    request: Request,
    backup_id: int,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    backup = db.get(Backup, backup_id)
    if backup is None or backup.owner_id != user.id:
        _flash(request, "❌ Backup not found.")
        return RedirectResponse("/backups", status_code=303)
    (config.BACKUPS_DIR / backup.filename).unlink(missing_ok=True)
    db.delete(backup)
    db.commit()
    _flash(request, "🗑️ Backup deleted.")
    return RedirectResponse("/backups", status_code=303)


@router.post("/restore")
async def restore_backup(
    request: Request,
    file: UploadFile = File(...),
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    if not (file.filename or "").endswith(".zip"):
        _flash(request, "❌ Please upload a .zip backup archive.")
        return RedirectResponse("/backups", status_code=303)
    # Save the upload to a temp path, then restore through the provider.
    tmp = config.BACKUPS_DIR / f"_restore-{user.username}.zip"
    with tmp.open("wb") as out:
        while chunk := await file.read(1024 * 1024):
            out.write(chunk)
    try:
        summary = get_provider().restore_backup(tmp)
        _flash(request, f"♻️ Restore complete ({len(summary['items'])} files).")
    except Exception as exc:  # noqa: BLE001 — surface any archive error to the user
        _flash(request, f"❌ Restore failed: {exc}")
    finally:
        tmp.unlink(missing_ok=True)
    return RedirectResponse("/backups", status_code=303)
