"""Helpers for per-account system-user isolation."""
from __future__ import annotations

from pathlib import Path

from sqlalchemy.orm import Session

from .models import User
from .providers import get_provider


def account_home(db: Session, user: User) -> Path:
    """Ensure the user has a system account and return its home directory.

    Idempotent: assigns a system_user (the panel username) the first time and
    provisions the Linux user + PHP-FPM pool via the provider.
    """
    if not user.system_user:
        user.system_user = user.username
        db.commit()
    return Path(get_provider().ensure_account(user.system_user))
