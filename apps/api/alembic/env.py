from __future__ import annotations

import os

import app.models  # noqa: F401  (registers all tables on Base metadata)
from alembic import context
from app.core.config import get_settings
from app.core.db import Base
from sqlalchemy import engine_from_config, pool

target_metadata = Base.metadata

config = context.config


def _database_url() -> str:
    from sqlalchemy.engine.url import make_url
    url = os.getenv("DATABASE_URL") or get_settings().database_url
    # alembic uses sync engines only
    return make_url(url).render_as_string(hide_password=False)


def run_migrations_offline() -> None:
    context.configure(
        url=_database_url(),
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    configuration = config.get_section(config.config_ini_section, {})
    configuration["sqlalchemy.url"] = _database_url()
    connectable = engine_from_config(
        configuration,
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    with connectable.connect() as connection:
        context.configure(connection=connection, target_metadata=target_metadata)
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
