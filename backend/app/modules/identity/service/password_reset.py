from app.core.exceptions import DependencyUnavailableError, RateLimitedError
from app.modules.identity.domain.emails import email_fingerprint
from app.modules.identity.domain.enums import EmailPurpose, TokenPurpose
from app.modules.identity.domain.exceptions import InvalidTokenError, WeakPasswordError
from app.modules.identity.domain.limits import PASSWORD_RESET_EMAIL_LIMIT, PASSWORD_RESET_IP_LIMIT
from app.modules.identity.domain.passwords import normalize_password
from app.modules.identity.service.dto import PasswordResetDTO, PasswordResetRequestDTO
from app.modules.identity.service.ports import (
    BreachedPasswordChecker,
    OneTimeTokenStore,
    PasswordHasher,
    RateLimiter,
    SecurityEvents,
    UnitOfWork,
)

PASSWORD_RESET_EMAIL_PREFIX = "password_reset_email:"  # noqa: S105
PASSWORD_RESET_IP_PREFIX = "password_reset_ip:"  # noqa: S105
UNKNOWN_IP = "unknown"


async def request_password_reset(
    reset_request: PasswordResetRequestDTO,
    uow: UnitOfWork,
    limiter: RateLimiter,
    events: SecurityEvents,
    secret: bytes,
) -> None:
    ip_key = PASSWORD_RESET_IP_PREFIX + (reset_request.client_ip or UNKNOWN_IP)
    retry_after = await limiter.hit(ip_key, PASSWORD_RESET_IP_LIMIT)
    if retry_after is not None:
        events.rate_limited("password_reset", "ip")
        raise RateLimitedError("Password reset rate limit exceeded", retry_after)
    email_key = PASSWORD_RESET_EMAIL_PREFIX + email_fingerprint(reset_request.email, secret)
    retry_after = await limiter.hit(email_key, PASSWORD_RESET_EMAIL_LIMIT)
    if retry_after is not None:
        events.rate_limited("password_reset", "email")
        raise RateLimitedError("Password reset rate limit exceeded", retry_after)
    async with uow:
        user = await uow.users.find_by_email(reset_request.email)
        if user is not None:
            await uow.email_jobs.enqueue(EmailPurpose.PASSWORD_RESET, user.id)
            await uow.commit()
    events.password_reset_requested(user_id=user.id if user else None)


class PasswordResetService:
    def __init__(
        self,
        uow: UnitOfWork,
        tokens: OneTimeTokenStore,
        hasher: PasswordHasher,
        breach_checker: BreachedPasswordChecker,
        events: SecurityEvents,
    ):
        self._uow = uow
        self._tokens = tokens
        self._hasher = hasher
        self._breach_checker = breach_checker
        self._events = events

    async def reset(self, reset: PasswordResetDTO) -> None:
        password = normalize_password(reset.password)
        token = await self._tokens.peek(TokenPurpose.PASSWORD_RESET, reset.token)
        if token is None:
            raise InvalidTokenError()
        await self._check_breach(password)
        password_hash = await self._hasher.hash_password(password)
        async with self._uow:
            user = await self._uow.users.get_for_update(token.user_id)
            if user is None or user.credentials_version != token.credentials_version:
                raise InvalidTokenError()
            await self._uow.passwords.set_hash(user.id, password_hash)
            await self._uow.users.mark_email_verified(user.id)
            await self._uow.users.bump_credentials_version(user.id)
            await self._uow.commit()
        self._events.password_reset_completed(user.id)
        try:
            await self._tokens.consume(TokenPurpose.PASSWORD_RESET, reset.token)
        except DependencyUnavailableError:
            self._events.reset_token_cleanup_failed()

    async def _check_breach(self, password: str) -> None:
        breached = await self._breach_checker.is_breached(password)
        if breached is None:
            self._events.breach_check_unavailable()
        if breached:
            raise WeakPasswordError("breached")
