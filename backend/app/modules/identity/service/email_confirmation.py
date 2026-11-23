from app.core.exceptions import RateLimitedError
from app.modules.identity.domain.emails import email_fingerprint
from app.modules.identity.domain.enums import EmailPurpose, TokenPurpose
from app.modules.identity.domain.exceptions import InvalidTokenError
from app.modules.identity.domain.limits import (
    RESEND_CONFIRMATION_EMAIL_LIMIT,
    RESEND_CONFIRMATION_IP_LIMIT,
)
from app.modules.identity.service.dto import ResendConfirmationDTO
from app.modules.identity.service.ports import (
    OneTimeTokenStore,
    RateLimiter,
    SecurityEvents,
    UnitOfWork,
)

RESEND_CONFIRMATION_EMAIL_PREFIX = "resend_confirmation_email:"
RESEND_CONFIRMATION_IP_PREFIX = "resend_confirmation_ip:"
UNKNOWN_IP = "unknown"


async def confirm_email(
    token: str, tokens: OneTimeTokenStore, uow: UnitOfWork, events: SecurityEvents
) -> None:
    user_id = await tokens.consume(TokenPurpose.EMAIL_CONFIRM, token)
    if user_id is None:
        raise InvalidTokenError()
    async with uow:
        await uow.users.mark_email_verified(user_id=user_id)
        await uow.commit()
    events.email_confirmed(user_id=user_id)


async def resend_confirmation(
    request: ResendConfirmationDTO,
    uow: UnitOfWork,
    limiter: RateLimiter,
    secret: bytes,
    events: SecurityEvents,
) -> None:
    ip_key = RESEND_CONFIRMATION_IP_PREFIX + (request.client_ip or UNKNOWN_IP)
    retry_after = await limiter.hit(ip_key, RESEND_CONFIRMATION_IP_LIMIT)
    if retry_after is not None:
        events.rate_limited("resend_confirmation", "ip")
        raise RateLimitedError("Resend confirmation rate limit exceeded", retry_after)
    email_key = RESEND_CONFIRMATION_EMAIL_PREFIX + email_fingerprint(request.email, secret)
    retry_after = await limiter.hit(email_key, RESEND_CONFIRMATION_EMAIL_LIMIT)
    if retry_after is not None:
        events.rate_limited("resend_confirmation", "email")
        raise RateLimitedError("Resend confirmation rate limit exceeded", retry_after)
    async with uow:
        user = await uow.users.find_by_email(request.email)
        if user is None or user.email_verified_at is not None:
            return
        await uow.email_jobs.enqueue(EmailPurpose.EMAIL_CONFIRM, user.id)
        await uow.commit()
