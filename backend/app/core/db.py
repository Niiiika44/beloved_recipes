from collections.abc import AsyncIterator
from functools import lru_cache

from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from app.core.config import get_settings


@lru_cache(maxsize=1)
def get_engine() -> AsyncEngine:
    settings = get_settings()
    connect_args = {
        "server_settings": {
            "statement_timeout": str(settings.db.statement_timeout_ms),
            "idle_in_transaction_session_timeout": str(settings.db.idle_in_transaction_timeout_ms),
        }
    }
    return create_async_engine(
        settings.db.dsn,
        echo=False,
        pool_size=settings.db.pool_size,
        max_overflow=settings.db.max_overflow,
        pool_recycle=settings.db.pool_recycle_seconds,
        pool_pre_ping=True,
        connect_args=connect_args,
    )


async def dispose_engine() -> None:
    engine = get_engine()
    await engine.dispose()
    get_engine.cache_clear()
    get_session_factory.cache_clear()


@lru_cache(maxsize=1)
def get_session_factory() -> async_sessionmaker[AsyncSession]:
    return async_sessionmaker(bind=get_engine(), expire_on_commit=False)


async def get_session() -> AsyncIterator[AsyncSession]:
    """Provides a database session for dependency injection."""
    async_session_local = get_session_factory()
    async with async_session_local() as session:
        yield session
