from app.core.exceptions import RateLimitedError
from app.modules.identity.domain.emails import email_fingerprint
from app.modules.identity.domain.enums import EmailPurpose
from app.modules.identity.domain.exceptions import WeakPasswordError
from app.modules.identity.domain.limits import (
    REGISTRATION_EMAIL_LIMIT,
    REGISTRATION_IP_LIMIT,
)
from app.modules.identity.domain.passwords import normalize_password
from app.modules.identity.domain.profile import normalize_display_name
from app.modules.identity.service.dto import RegistrationDTO
from app.modules.identity.service.ports import (
    BreachedPasswordChecker,
    PasswordHasher,
    RateLimiter,
    SecurityEvents,
    UnitOfWork,
)

REGISTRATION_EMAIL_PREFIX = "registration_email:"
REGISTRATION_IP_PREFIX = "registration_ip:"
UNKNOWN_IP = "unknown"


class RegistrationService:
    def __init__(
        self,
        uow: UnitOfWork,
        limiter: RateLimiter,
        hasher: PasswordHasher,
        breach_checker: BreachedPasswordChecker,
        events: SecurityEvents,
        secret: bytes,
    ):
        self._uow = uow
        self._limiter = limiter
        self._hasher = hasher
        self._breach_checker = breach_checker
        self._events = events
        self._secret = secret

    async def register(self, registration: RegistrationDTO) -> None:
        password = normalize_password(registration.password)
        display_name = normalize_display_name(registration.display_name)
        await self._check_limits(registration)
        await self._check_breach(password)
        password_hash = await self._hasher.hash_password(password)
        await self._save(registration.email, display_name, password_hash)

    async def _check_limits(self, registration: RegistrationDTO) -> None:
        ip_key = REGISTRATION_IP_PREFIX + (registration.client_ip or UNKNOWN_IP)
        retry_after = await self._limiter.hit(ip_key, REGISTRATION_IP_LIMIT)
        if retry_after is not None:
            self._events.rate_limited("registration", "ip")
            raise RateLimitedError("Registration rate limit exceeded", retry_after)
        email_key = REGISTRATION_EMAIL_PREFIX + email_fingerprint(registration.email, self._secret)
        retry_after = await self._limiter.hit(email_key, REGISTRATION_EMAIL_LIMIT)
        if retry_after is not None:
            self._events.rate_limited("registration", "email")
            raise RateLimitedError("Registration rate limit exceeded", retry_after)

    async def _check_breach(self, password: str) -> None:
        breached = await self._breach_checker.is_breached(password)
        if breached is None:
            self._events.breach_check_unavailable()
        if breached:
            raise WeakPasswordError("breached")

    async def _save(self, email: str, display_name: str, password_hash: str) -> None:
        async with self._uow:
            user_id = await self._uow.users.create(email=email, display_name=display_name)
            if user_id is None:
                user = await self._uow.users.find_by_email(email=email)
                if user is not None:
                    await self._uow.email_jobs.enqueue(
                        purpose=EmailPurpose.ALREADY_REGISTERED, user_id=user.id
                    )
            else:
                await self._uow.passwords.set_hash(user_id=user_id, password_hash=password_hash)
                await self._uow.email_jobs.enqueue(
                    purpose=EmailPurpose.EMAIL_CONFIRM, user_id=user_id
                )
            await self._uow.commit()
