"""Metrics — per-domain Visitors, Errors and Bandwidth on one page.

cPanel exposes Visitors / Errors / Bandwidth as separate icons that all drill
into the same access/error logs; we mirror that with a single page and a domain
selector. The provider only locates+reads a domain's raw nginx logs; all the
counting lives in app.weblog, so demo (synthetic seeded logs) and linux (real
nginx logs) render identically.

Ownership is enforced here: a user may only view metrics for a domain they own,
so the domain name handed to the provider is always one of the caller's rows —
never arbitrary client input.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import weblog
from ..db import get_db
from ..models import Domain, User
from ..providers import get_provider
from ..security import current_user
from ..web import templates

router = APIRouter(prefix="/metrics", tags=["metrics"])


@router.get("")
def metrics_home(
    request: Request,
    domain: str | None = None,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    domains = db.scalars(
        select(Domain).where(Domain.owner_id == user.id).order_by(Domain.name)
    ).all()

    # Only ever read logs for a domain the caller owns. An unknown/other-owner
    # `domain` query param falls back to the first owned domain.
    owned = {d.name: d for d in domains}
    selected = domain if domain in owned else (domains[0].name if domains else None)

    stats = None
    errors: list[str] = []
    if selected:
        provider = get_provider()
        stats = weblog.parse_access_log(provider.read_access_log(selected))
        errors = weblog.parse_error_log(provider.read_error_log(selected))

    # Scale the per-day bars against the busiest day (visual only).
    if stats and stats["by_day"]:
        busiest = max(c for _, c in stats["by_day"])
        by_day = [
            {"day": day, "count": count,
             "bar": round(count / busiest * 100, 1) if busiest else 0}
            for day, count in stats["by_day"]
        ]
    else:
        by_day = []

    flash = request.session.pop("flash", None)
    return templates.TemplateResponse(
        request,
        "metrics.html",
        {
            "user": user,
            "active": "metrics",
            "flash": flash,
            "domains": domains,
            "selected": selected,
            "stats": stats,
            "errors": errors,
            "by_day": by_day,
        },
    )
