"""Disk Usage — a real per-domain / per-directory breakdown of the account's
on-disk footprint, cPanel "Disk Usage" style.

Computed directly from the account's site directories (the docroot's parent,
i.e. /home/<user>/<domain>). No provider call is needed: walking the tree is
demo-safe and works identically on linux, so this page has no host-specific
behaviour and needs no model or migration.
"""
from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, Depends, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..db import get_db
from ..models import Domain, User
from ..security import current_user
from ..web import templates

router = APIRouter(prefix="/disk-usage", tags=["disk-usage"])

# Cap the per-site directory walk so a pathological tree can't stall the
# single-worker event loop. Sites larger than this are still summed at the top
# level; only the sub-directory breakdown is bounded.
_MAX_ENTRIES = 50_000


def _dir_size(path: Path) -> int:
    """Total size in bytes of every regular file under ``path`` (bounded)."""
    total = 0
    seen = 0
    for f in path.rglob("*"):
        seen += 1
        if seen > _MAX_ENTRIES:
            break
        try:
            if f.is_file() and not f.is_symlink():
                total += f.stat().st_size
        except OSError:
            continue
    return total


def _fmt(nbytes: float) -> str:
    """Human-readable size (B / KB / MB / GB)."""
    val = float(nbytes)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if val < 1024 or unit == "TB":
            return f"{val:.0f} {unit}" if unit == "B" else f"{val:.1f} {unit}"
        val /= 1024
    return f"{val:.1f} TB"


@router.get("")
def disk_usage(request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)):
    domains = db.scalars(
        select(Domain).where(Domain.owner_id == user.id).order_by(Domain.name)
    ).all()

    sites = []
    total_bytes = 0
    for d in domains:
        site = Path(d.docroot).parent  # /home/<user>/<domain>
        size = _dir_size(site) if site.exists() else 0
        total_bytes += size

        # One level of breakdown: immediate sub-directories of the site root.
        children = []
        if site.exists():
            try:
                for child in sorted(site.iterdir()):
                    if child.is_dir() and not child.is_symlink():
                        csize = _dir_size(child)
                        children.append({"name": child.name, "bytes": csize,
                                         "display": _fmt(csize)})
            except OSError:
                pass
        children.sort(key=lambda c: c["bytes"], reverse=True)

        sites.append({
            "name": d.name,
            "path": str(site),
            "bytes": size,
            "display": _fmt(size),
            "children": children,
        })

    sites.sort(key=lambda s: s["bytes"], reverse=True)

    # Account quota (MB) → percentage bar; 0 / unlimited admins show ∞.
    quota_mb = 0 if user.unlimited else (user.eff_disk_mb or 0)
    used_mb = round(total_bytes / (1024 * 1024), 1)
    percent = min(100, round(used_mb / quota_mb * 100, 1)) if quota_mb else 0

    # A relative bar width for each site vs the largest site (visual only).
    largest = max((s["bytes"] for s in sites), default=0)
    for s in sites:
        s["bar"] = round(s["bytes"] / largest * 100, 1) if largest else 0

    flash = request.session.pop("flash", None)
    return templates.TemplateResponse(
        request,
        "disk_usage.html",
        {
            "user": user,
            "active": "disk_usage",
            "flash": flash,
            "sites": sites,
            "total_display": _fmt(total_bytes),
            "used_mb": used_mb,
            "quota_mb": quota_mb,
            "percent": percent,
        },
    )
