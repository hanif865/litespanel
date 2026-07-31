"""Log viewer — admin-only access/error log inspection.

Viewing system logs is an admin feature. The provider owns a fixed allowlist of
readable log files (nginx access/error, auth, fail2ban, the panel's own journal,
…); this router only ever passes back an opaque `key` from that list, never a
filesystem path — so the viewer cannot be coaxed into reading arbitrary files.
The line count is capped and an optional case-insensitive substring filter is
applied by the provider while tailing.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session

from ..db import get_db
from ..models import User
from ..providers import get_provider
from ..security import current_user
from ..web import templates

router = APIRouter(prefix="/logs", tags=["logs"])

_LINE_CHOICES = (100, 200, 500, 1000, 2000)


@router.get("")
def logs_home(
    request: Request,
    source: str | None = None,
    lines: int = 200,
    q: str | None = None,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    if user.role != "admin":
        request.session["flash"] = "❌ The log viewer is an admin-only feature."
        return RedirectResponse("/", status_code=303)

    provider = get_provider()
    sources = provider.log_sources()
    keys = {s["key"] for s in sources}

    # Pick the requested source, else the first available one.
    selected = source if source in keys else (sources[0]["key"] if sources else None)

    if lines not in _LINE_CHOICES:
        lines = 200
    grep = (q or "").strip() or None

    content = ""
    error = None
    if selected:
        ok, text = provider.read_log(selected, lines=lines, grep=grep)
        if ok:
            content = text
        else:
            error = text
    elif not sources:
        error = "No log sources are available on this host."

    return templates.TemplateResponse(
        request,
        "logs.html",
        {
            "user": user,
            "is_admin": True,
            "sources": sources,
            "selected": selected,
            "lines": lines,
            "line_choices": _LINE_CHOICES,
            "q": grep or "",
            "content": content,
            "error": error,
            "line_count": len(content.splitlines()) if content else 0,
            "active": "logs",
        },
    )
