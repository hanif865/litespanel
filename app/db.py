"""SQLAlchemy engine/session setup.

SQLite keeps the panel's own footprint tiny — no separate DB server process,
which matters on a 1GB/1CPU VPS.
"""
from __future__ import annotations

from collections.abc import Iterator

from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from . import config

# check_same_thread=False lets the connection be shared across FastAPI's
# threadpool; SQLite still serializes writes internally.
_connect_args = {"check_same_thread": False} if config.DB_URL.startswith("sqlite") else {}

engine = create_engine(config.DB_URL, connect_args=_connect_args, future=True)
SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False, future=True)


class Base(DeclarativeBase):
    pass


def get_db() -> Iterator[Session]:
    """FastAPI dependency yielding a request-scoped session."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db() -> None:
    """Bring the database schema up to date by running Alembic migrations.

    Alembic is the single source of truth for the schema: on a fresh database
    this applies the initial migration (creating every table); on an existing
    one it applies only new migrations. No more deleting the DB after a model
    change — add a migration instead.
    """
    from alembic import command
    from alembic.config import Config

    config.ensure_dirs()
    cfg = Config(str(config.BASE_DIR / "alembic.ini"))
    cfg.set_main_option("script_location", str(config.BASE_DIR / "migrations"))
    command.upgrade(cfg, "head")
