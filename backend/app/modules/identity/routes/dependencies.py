from datetime import UTC, datetime
from typing import Annotated

from fastapi import Depends, Request
from redis.asyncio import Redis
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.core.config import Settings, get_settings
from app.core.db import get_session_factory
from app.core.redis import get_redis
from app.modules.identity.infrastructure.pwned_passwords_checker import PwnedPasswordsChecker
from app.modules.identity.infrastructure.redis_login_state_store import RedisLoginStateStore
from app.modules.identity.infrastructure.redis_one_time_token_store import RedisOneTimeTokenStore
from app.modules.identity.infrastructure.redis_rate_limiter import RedisRateLimiter
from app.modules.identity.infrastructure.redis_session_store import RedisSessionStore
from app.modules.identity.infrastructure.structlog_security_events import StructlogSecurityEvents
from app.modules.identity.infrastructure.uow import SqlAlchemyUnitOfWork
from app.modules.identity.service.auth import authenticate
from app.modules.identity.service.dto import UserDTO
from app.modules.identity.service.google_login import GoogleLoginService
from app.modules.identity.service.nicknames import ensure_nickname
from app.modules.identity.service.password_change import PasswordChangeService
from app.modules.identity.service.password_login import PasswordLoginService
from app.modules.identity.service.password_reset import PasswordResetService
from app.modules.identity.service.ports import (
    BreachedPasswordChecker,
    LoginStateStore,
    OidcProvider,
    OneTimeTokenStore,
    PasswordHasher,
    RateLimiter,
    SecurityEvents,
    SessionStore,
    UnitOfWork,
)
from app.modules.identity.service.registration import RegistrationService


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


def get_rate_limiter(
    client: Annotated[Redis, Depends(get_redis)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> RateLimiter:
    return RedisRateLimiter(
        client=client, operation_timeout_seconds=settings.rate_limit.operation_timeout_seconds
    )


def get_one_time_token_store(
    client: Annotated[Redis, Depends(get_redis)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> OneTimeTokenStore:
    return RedisOneTimeTokenStore(
        client=client, operation_timeout_seconds=settings.token.operation_timeout_seconds
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


async def require_nickname(
    user: Annotated[
        UserDTO,
        Depends(get_current_user),
    ],
) -> UserDTO:
    return ensure_nickname(user)


async def get_password_hasher(request: Request) -> PasswordHasher:
    hasher: PasswordHasher = request.app.state.password_hasher
    return hasher


async def get_oidc_provider(request: Request) -> OidcProvider:
    provider: OidcProvider = request.app.state.oidc_provider
    return provider


def get_breach_checker() -> BreachedPasswordChecker:
    return PwnedPasswordsChecker()


def get_security_events() -> SecurityEvents:
    return StructlogSecurityEvents()


def get_secret(settings: Annotated[Settings, Depends(get_settings)]) -> bytes:
    return settings.security.secret_key.get_secret_value().encode()


def get_registration_service(
    uow: Annotated[UnitOfWork, Depends(get_uow)],
    limiter: Annotated[RateLimiter, Depends(get_rate_limiter)],
    hasher: Annotated[PasswordHasher, Depends(get_password_hasher)],
    breach_checker: Annotated[BreachedPasswordChecker, Depends(get_breach_checker)],
    events: Annotated[SecurityEvents, Depends(get_security_events)],
    secret: Annotated[bytes, Depends(get_secret)],
) -> RegistrationService:
    return RegistrationService(
        uow=uow,
        limiter=limiter,
        hasher=hasher,
        breach_checker=breach_checker,
        events=events,
        secret=secret,
    )


def get_password_login_service(
    uow: Annotated[UnitOfWork, Depends(get_uow)],
    limiter: Annotated[RateLimiter, Depends(get_rate_limiter)],
    hasher: Annotated[PasswordHasher, Depends(get_password_hasher)],
    sessions: Annotated[SessionStore, Depends(get_session_store)],
    events: Annotated[SecurityEvents, Depends(get_security_events)],
    secret: Annotated[bytes, Depends(get_secret)],
) -> PasswordLoginService:
    return PasswordLoginService(
        uow=uow,
        limiter=limiter,
        hasher=hasher,
        sessions=sessions,
        events=events,
        secret=secret,
    )


def get_password_reset_service(
    uow: Annotated[UnitOfWork, Depends(get_uow)],
    tokens: Annotated[OneTimeTokenStore, Depends(get_one_time_token_store)],
    hasher: Annotated[PasswordHasher, Depends(get_password_hasher)],
    breach_checker: Annotated[BreachedPasswordChecker, Depends(get_breach_checker)],
    events: Annotated[SecurityEvents, Depends(get_security_events)],
) -> PasswordResetService:
    return PasswordResetService(
        uow=uow, tokens=tokens, hasher=hasher, breach_checker=breach_checker, events=events
    )


def get_password_change_service(
    uow: Annotated[UnitOfWork, Depends(get_uow)],
    limiter: Annotated[RateLimiter, Depends(get_rate_limiter)],
    breach_checker: Annotated[BreachedPasswordChecker, Depends(get_breach_checker)],
    hasher: Annotated[PasswordHasher, Depends(get_password_hasher)],
    sessions: Annotated[SessionStore, Depends(get_session_store)],
    events: Annotated[SecurityEvents, Depends(get_security_events)],
) -> PasswordChangeService:
    return PasswordChangeService(
        uow=uow,
        limiter=limiter,
        hasher=hasher,
        breach_checker=breach_checker,
        sessions=sessions,
        events=events,
    )


def get_login_state_store(
    client: Annotated[Redis, Depends(get_redis)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> LoginStateStore:
    return RedisLoginStateStore(
        client=client, operation_timeout_seconds=settings.login_state.operation_timeout_seconds
    )


def get_google_login_service(
    uow: Annotated[UnitOfWork, Depends(get_uow)],
    provider: Annotated[OidcProvider, Depends(get_oidc_provider)],
    states: Annotated[LoginStateStore, Depends(get_login_state_store)],
    sessions: Annotated[SessionStore, Depends(get_session_store)],
    events: Annotated[SecurityEvents, Depends(get_security_events)],
    limiter: Annotated[RateLimiter, Depends(get_rate_limiter)],
) -> GoogleLoginService:
    return GoogleLoginService(
        uow=uow,
        provider=provider,
        states=states,
        sessions=sessions,
        events=events,
        limiter=limiter,
    )
