from app.core.exceptions import RateLimitedError
from app.modules.identity.domain.emails import email_fingerprint
from app.modules.identity.domain.enums import LoginMethod
from app.modules.identity.domain.exceptions import (
    EmailNotVerifiedError,
    InvalidCredentialsError,
    WeakPasswordError,
)
from app.modules.identity.domain.limits import LOGIN_EMAIL_LIMIT, LOGIN_IP_LIMIT
from app.modules.identity.domain.passwords import normalize_password
from app.modules.identity.service.dto import LoginDTO
from app.modules.identity.service.ports import (
    PasswordHasher,
    RateLimiter,
    SecurityEvents,
    SessionStore,
    UnitOfWork,
)

LOGIN_EMAIL_PREFIX = "login_email:"
LOGIN_IP_PREFIX = "login_ip:"
UNKNOWN_IP = "unknown"


class PasswordLoginService:
    def __init__(
        self,
        uow: UnitOfWork,
        limiter: RateLimiter,
        hasher: PasswordHasher,
        sessions: SessionStore,
        events: SecurityEvents,
        secret: bytes,
    ):
        self._uow = uow
        self._limiter = limiter
        self._hasher = hasher
        self._sessions = sessions
        self._events = events
        self._secret = secret

    async def login(self, login: LoginDTO) -> str:
        try:
            password = normalize_password(login.password)
        except WeakPasswordError:
            raise InvalidCredentialsError() from None
        await self._check_limits(login)
        async with self._uow:
            user = await self._uow.users.find_by_email(login.email)
            password_hash = await self._uow.passwords.get_hash(user.id) if user else None
        if user is None or password_hash is None:
            await self._hasher.verify_dummy(password)
            self._events.login_failed("bad_credentials")
            raise InvalidCredentialsError()
        password_verify = await self._hasher.verify(password_hash, password)
        if not password_verify.matches:
            self._events.login_failed("bad_credentials")
            raise InvalidCredentialsError()
        if user.email_verified_at is None:
            self._events.login_failed("email_not_verified")
            raise EmailNotVerifiedError()
        if password_verify.needs_rehash:
            password_hash = await self._hasher.hash_password(password)
            async with self._uow:
                await self._uow.passwords.set_hash(user_id=user.id, password_hash=password_hash)
                await self._uow.commit()
        if login.current_token is not None:
            await self._sessions.revoke(login.current_token)
        token = await self._sessions.create(user_id=user.id)
        self._events.login_succeeded(user_id=user.id, method=LoginMethod.PASSWORD)
        return token

    async def _check_limits(self, login: LoginDTO) -> None:
        ip_key = LOGIN_IP_PREFIX + (login.client_ip or UNKNOWN_IP)
        retry_after = await self._limiter.hit(ip_key, LOGIN_IP_LIMIT)
        if retry_after is not None:
            self._events.rate_limited("login", "ip")
            raise RateLimitedError("Login rate limit exceeded", retry_after)
        email_key = LOGIN_EMAIL_PREFIX + email_fingerprint(login.email, self._secret)
        retry_after = await self._limiter.hit(email_key, LOGIN_EMAIL_LIMIT)
        if retry_after is not None:
            self._events.rate_limited("login", "email")
            raise RateLimitedError("Login rate limit exceeded", retry_after)
