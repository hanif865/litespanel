"""Alembic environment.

Wires Alembic to the app's SQLAlchemy metadata and DB URL, with SQLite batch
mode enabled so ALTER-heavy migrations (add/drop/alter column) work on SQLite.
"""
from __future__ import annotations

from logging.config import fileConfig

from alembic import context
from sqlalchemy import engine_from_config, pool

# Import the app's metadata + config. prepend_sys_path=. (alembic.ini) makes
# the "app" package importable when running the CLI from the project root.
from app import config as app_config
from app.db import Base
import app.models  # noqa: F401 — register all tables on Base.metadata

config = context.config
if config.config_file_name is not None:
    # disable_existing_loggers=False so running migrations programmatically at
    # app startup doesn't silence uvicorn's already-configured loggers.
    fileConfig(config.config_file_name, disable_existing_loggers=False)

# Ensure the data dir exists (SQLite file lives there) and inject the URL.
app_config.ensure_dirs()
config.set_main_option("sqlalchemy.url", app_config.DB_URL)

target_metadata = Base.metadata


def run_migrations_offline() -> None:
    context.configure(
        url=config.get_main_option("sqlalchemy.url"),
        target_metadata=target_metadata,
        literal_binds=True,
        render_as_batch=True,
        compare_type=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            render_as_batch=True,   # SQLite-safe ALTERs
            compare_type=True,
        )
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
