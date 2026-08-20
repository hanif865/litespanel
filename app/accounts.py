"""Helpers for per-account system-user isolation."""
from __future__ import annotations

import shutil
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import Session

from . import config
from .models import CronJob, User
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


def terminate_account(db: Session, target: User) -> str:
    """Tear down a hosting account and all its resources, then delete the row.

    Removes the target's sites/subdomains, drops its databases, deletes its
    backup archives, and removes the whole isolated system account (system user,
    /home, PHP-FPM pool). The DB row is then deleted (cascading domains,
    databases, cron jobs and backups), the web server reloaded, and the managed
    crontab re-synced so the gone user's jobs disappear.

    Shared by the User Manager (/users) and the WHM area (/whm) so both go
    through one vetted teardown path. Returns the removed username. The caller
    is responsible for the permission check (only act on accounts you manage).
    """
    provider = get_provider()
    # Tear down the target's system artifacts before removing DB rows.
    for domain in list(target.domains):
        for sub in list(domain.subdomains):
            provider.remove_subdomain(sub.fqdn)
        provider.remove_site(domain.name)
    for database in list(target.databases):
        provider.drop_database(database.name, database.db_user)
    # Drop the account's standalone DB users/roles too (their grants go with
    # them). The panel rows cascade off the User row below.
    for db_user in list(target.db_users):
        provider.drop_db_user(db_user.username)
    for pg_user in list(target.pg_users):
        provider.drop_pg_user(pg_user.username)
    for backup in list(target.backups):
        (config.BACKUPS_DIR / backup.filename).unlink(missing_ok=True)
    # Remove the whole isolated account (system user, /home, PHP-FPM pool).
    if target.system_user:
        provider.remove_account(target.system_user)
    else:
        for domain in list(target.domains):
            shutil.rmtree(Path(domain.docroot).parent, ignore_errors=True)

    username = target.username
    db.delete(target)          # cascades domains/databases/cron/backups/db-users + nested rows
    db.commit()
    provider.reload_web()
    # Re-sync the crontab now that this user's jobs are gone.
    remaining = db.scalars(select(CronJob).order_by(CronJob.id)).all()
    provider.sync_cron([f"{j.schedule} {j.command}" for j in remaining])
    return username
