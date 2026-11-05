import asyncio
from logging.config import fileConfig
from typing import Any

from sqlalchemy import MetaData, pool
from sqlalchemy.engine import Connection
from sqlalchemy.ext.asyncio import async_engine_from_config

from alembic import context
from alembic.operations.ops import MigrationScript
from alembic.runtime.migration import MigrationContext
from alembic.script import ScriptDirectory
from app.core.config import get_settings
from app.core.models import Base
import app.modules.identity.infrastructure.models  # noqa: F401

settings = get_settings()

config = context.config
config.set_main_option("sqlalchemy.url", settings.db.dsn)

if config.config_file_name is not None:
    fileConfig(config.config_file_name, disable_existing_loggers=False)

target_metadata: MetaData = Base.metadata


def assign_sequential_revision_id(
    migration_context: MigrationContext,
    revision: Any,
    directives: list[MigrationScript],
) -> None:
    """Number new revisions 0001, 0002, ... instead of random hashes."""
    head = ScriptDirectory.from_config(config).get_current_head()
    next_number = int(head) + 1 if head is not None else 1
    for directive in directives:
        directive.rev_id = f"{next_number:04d}"


def run_migrations_offline() -> None:
    """Run migrations in 'offline' mode.

    This configures the context with just a URL
    and not an Engine, though an Engine is acceptable
    here as well.  By skipping the Engine creation
    we don't even need a DBAPI to be available.

    Calls to context.execute() here emit the given string to the
    script output.

    """
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        compare_type=True,
        compare_server_default=True,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )

    with context.begin_transaction():
        context.run_migrations()


def do_run_migrations(connection: Connection) -> None:
    context.configure(
        connection=connection,
        target_metadata=target_metadata,
        compare_type=True,
        compare_server_default=True,
        process_revision_directives=assign_sequential_revision_id,
    )

    with context.begin_transaction():
        context.run_migrations()


async def run_async_migrations() -> None:
    """In this scenario we need to create an Engine
    and associate a connection with the context.

    """
    connect_args = {"server_settings": {"lock_timeout": "4000"}}

    connectable = async_engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
        connect_args=connect_args,
    )

    async with connectable.connect() as connection:
        await connection.run_sync(do_run_migrations)

    await connectable.dispose()


def run_migrations_online() -> None:
    """Run migrations in 'online' mode."""

    asyncio.run(run_async_migrations())


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
