from app.core.exceptions import RateLimitedError
from app.modules.identity.domain.exceptions import (
    InvalidCredentialsError,
    InvalidSessionError,
    PasswordNotSetError,
    WeakPasswordError,
)
from app.modules.identity.domain.limits import PASSWORD_CHANGE_LIMIT
from app.modules.identity.domain.passwords import normalize_password
from app.modules.identity.service.dto import PasswordChangeDTO, UserDTO
from app.modules.identity.service.ports import (
    BreachedPasswordChecker,
    PasswordHasher,
    RateLimiter,
    SecurityEvents,
    SessionStore,
    UnitOfWork,
)

PASSWORD_CHANGE_PREFIX = "password_change:"  # noqa: S105


class PasswordChangeService:
    def __init__(
        self,
        uow: UnitOfWork,
        limiter: RateLimiter,
        hasher: PasswordHasher,
        breach_checker: BreachedPasswordChecker,
        sessions: SessionStore,
        events: SecurityEvents,
    ):
        self._uow = uow
        self._limiter = limiter
        self._hasher = hasher
        self._breach_checker = breach_checker
        self._sessions = sessions
        self._events = events

    async def change(self, user: UserDTO, change: PasswordChangeDTO) -> str:
        try:
            old_password = normalize_password(change.current)
        except WeakPasswordError:
            raise InvalidCredentialsError() from None
        new_password = normalize_password(change.new)

        key = PASSWORD_CHANGE_PREFIX + str(user.id)
        retry_after = await self._limiter.hit(key, PASSWORD_CHANGE_LIMIT)
        if retry_after is not None:
            self._events.rate_limited("password_change", "user")
            raise RateLimitedError("Password change rate limit exceeded", retry_after)

        async with self._uow:
            password_hash = await self._uow.passwords.get_hash(user.id)
            if password_hash is None:
                raise PasswordNotSetError()
        verify = await self._hasher.verify(password_hash, old_password)
        if not verify.matches:
            raise InvalidCredentialsError()
        await self._check_breach(new_password)
        new_password_hash = await self._hasher.hash_password(new_password)
        async with self._uow:
            fresh = await self._uow.users.get_for_update(user.id)
            if fresh is None:
                raise InvalidSessionError()
            await self._uow.passwords.set_hash(user.id, new_password_hash)
            new_version = await self._uow.users.bump_credentials_version(user.id)
            await self._uow.commit()
        token = await self._sessions.create(user.id, new_version)
        self._events.password_changed(user.id)
        return token

    async def _check_breach(self, password: str) -> None:
        breached = await self._breach_checker.is_breached(password)
        if breached is None:
            self._events.breach_check_unavailable()
        if breached:
            raise WeakPasswordError("breached")
