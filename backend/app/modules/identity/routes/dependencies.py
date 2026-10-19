from datetime import UTC, datetime
from typing import Annotated

from fastapi import Depends, Request
from redis.asyncio import Redis
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.core.config import Settings, get_settings
from app.core.db import get_session_factory
from app.core.redis import get_redis
from app.modules.identity.infrastructure.redis_session_store import RedisSessionStore
from app.modules.identity.infrastructure.uow import SqlAlchemyUnitOfWork
from app.modules.identity.service.auth import authenticate
from app.modules.identity.service.dto import UserDTO
from app.modules.identity.service.ports import SessionStore, UnitOfWork


def get_session_store(
    client: Annotated[Redis, Depends(get_redis)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> SessionStore:
    return RedisSessionStore(
        client=client,
        idle_ttl_seconds=settings.session.idle_ttl_seconds,
        absolute_ttl_seconds=settings.session.absolute_ttl_seconds,
        operation_timeout_seconds=settings.session.operation_timeout_seconds,
        now=lambda: datetime.now(UTC),
    )


def get_uow(
    session_factory: Annotated[async_sessionmaker[AsyncSession], Depends(get_session_factory)],
) -> UnitOfWork:
    return SqlAlchemyUnitOfWork(session_factory)


async def get_current_user(
    request: Request,
    settings: Annotated[Settings, Depends(get_settings)],
    uow: Annotated[UnitOfWork, Depends(get_uow)],
    store: Annotated[SessionStore, Depends(get_session_store)],
) -> UserDTO:
    token = request.cookies.get(settings.session.cookie_name)
    user = await authenticate(token=token, store=store, uow=uow)
    request.state.user_id = user.id
    return user
