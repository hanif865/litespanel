"""Home page — cPanel-style tool grid + statistics sidebar."""
from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .. import config
from ..db import get_db
from ..models import Certificate, Database, Domain, User
from ..providers import get_provider
from ..security import current_user
from ..web import templates

router = APIRouter(tags=["home"])


@router.get("/", response_class=HTMLResponse)
def home(request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)):
    stats = get_provider().system_stats()
    counts = {
        "domains": db.scalar(select(func.count()).select_from(Domain).where(Domain.owner_id == user.id)),
        "databases": db.scalar(select(func.count()).select_from(Database).where(Database.owner_id == user.id)),
        "certificates": db.scalar(
            select(func.count())
            .select_from(Certificate)
            .join(Domain)
            .where(Domain.owner_id == user.id)
        ),
    }
    primary = db.scalar(
        select(Domain).where(Domain.owner_id == user.id).order_by(Domain.created_at).limit(1)
    )
    info = {
        "primary_domain": primary.name if primary else "—",
        "home_dir": str(config.SITES_DIR),
    }
    return templates.TemplateResponse(
        request,
        "home.html",
        {"user": user, "stats": stats, "counts": counts, "info": info, "active": "home"},
    )
