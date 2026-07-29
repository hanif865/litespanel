"""Home page — cPanel-style tool grid + per-account statistics sidebar."""
from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..db import get_db
from ..models import Certificate, Database, Domain, EmailAccount, User
from ..providers import get_provider
from ..security import current_user
from ..web import templates

router = APIRouter(tags=["home"])


def _account_disk_mb(domains: list[Domain]) -> float:
    """Sum the on-disk size of all the account's site directories (MB)."""
    total = 0
    for d in domains:
        site = Path(d.docroot).parent  # /home/<user>/<domain>
        if site.exists():
            for f in site.rglob("*"):
                try:
                    if f.is_file():
                        total += f.stat().st_size
                except OSError:
                    continue
    return round(total / (1024 * 1024), 1)


def _meter(used: float, limit: float) -> dict:
    """Build a usage meter: percentage + a display string (limit 0 = unlimited)."""
    if not limit:
        return {"used": used, "limit": 0, "percent": 0, "display": f"{used} / ∞"}
    pct = min(100, round(used / limit * 100, 1)) if limit else 0
    return {"used": used, "limit": limit, "percent": pct, "display": f"{used} / {limit}"}


@router.get("/", response_class=HTMLResponse)
def home(request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)):
    server = get_provider().system_stats()  # whole-host CPU/mem for context
    domains = list(db.scalars(select(Domain).where(Domain.owner_id == user.id)))
    owned_domain_ids = [d.id for d in domains]

    n_databases = db.scalar(
        select(func.count()).select_from(Database).where(Database.owner_id == user.id)
    ) or 0
    n_email = db.scalar(
        select(func.count()).select_from(EmailAccount).where(EmailAccount.domain_id.in_(owned_domain_ids or [0]))
    ) or 0
    n_certs = db.scalar(
        select(func.count()).select_from(Certificate).join(Domain).where(Domain.owner_id == user.id)
    ) or 0

    # Per-account usage vs the account's limits (0 = unlimited / admin).
    disk_used = _account_disk_mb(domains)
    usage = {
        "disk": {**_meter(disk_used, 0 if user.unlimited else user.eff_disk_mb),
                 "display": f"{disk_used} / {'∞' if user.unlimited or not user.eff_disk_mb else str(user.eff_disk_mb)} MB"},
        "domains": _meter(len(domains), 0 if user.unlimited else user.eff_domains),
        "databases": _meter(n_databases, 0 if user.unlimited else user.eff_databases),
        "email": _meter(n_email, 0 if user.unlimited else user.eff_email),
        "certificates": n_certs,
    }

    primary = domains[0] if domains else None
    if primary:
        home_dir = str(Path(primary.docroot).parent.parent)  # /home/<user>
    elif user.system_user:
        home_dir = f"/home/{user.system_user}"
    else:
        home_dir = "—"
    info = {"primary_domain": primary.name if primary else "—", "home_dir": home_dir}

    return templates.TemplateResponse(
        request,
        "home.html",
        {"user": user, "server": server, "usage": usage, "info": info, "active": "home"},
    )
