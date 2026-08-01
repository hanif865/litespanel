"""Per-account resource limit checks for the multi-user / reseller model.

A limit of 0 means unlimited; admins are always unlimited.
"""
from __future__ import annotations

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .models import Database, Domain, EmailAccount, PgDatabase, User


def _count(db: Session, model, owner_id: int) -> int:
    return db.scalar(select(func.count()).select_from(model).where(model.owner_id == owner_id)) or 0


def domain_limit_reached(db: Session, user: User) -> bool:
    if user.unlimited or user.eff_domains == 0:
        return False
    return _count(db, Domain, user.id) >= user.eff_domains


def database_limit_reached(db: Session, user: User) -> bool:
    if user.unlimited or user.eff_databases == 0:
        return False
    return _count(db, Database, user.id) >= user.eff_databases


def pg_database_limit_reached(db: Session, user: User) -> bool:
    # PostgreSQL databases count against the same per-account database quota as
    # MySQL, so the two engines share one total (like cPanel's account limit).
    if user.unlimited or user.eff_databases == 0:
        return False
    total = _count(db, Database, user.id) + _count(db, PgDatabase, user.id)
    return total >= user.eff_databases


def email_limit_reached(db: Session, user: User) -> bool:
    if user.unlimited or user.eff_email == 0:
        return False
    # EmailAccount has no owner_id; count via the owned domains.
    owned = select(Domain.id).where(Domain.owner_id == user.id).scalar_subquery()
    current = db.scalar(
        select(func.count()).select_from(EmailAccount).where(EmailAccount.domain_id.in_(owned))
    ) or 0
    return current >= user.eff_email
