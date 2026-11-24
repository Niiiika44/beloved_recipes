from dataclasses import dataclass
from datetime import timedelta

import structlog

from app.core.exceptions import DependencyUnavailableError
from app.modules.identity.domain.enums import EmailPurpose, TokenPurpose
from app.modules.identity.domain.mail import (
    EMAIL_CONFIRM_TOKEN_TTL,
    MAIL_MAX_ATTEMPTS,
    PASSWORD_RESET_TOKEN_TTL,
    retry_delay,
)
from app.modules.identity.service.dto import EmailJobDTO, UserDTO
from app.modules.identity.service.exceptions import (
    MailDeliveryPermanentError,
    MailDeliveryTemporaryError,
)
from app.modules.identity.service.ports import Mailer, OneTimeTokenStore, UnitOfWork

logger = structlog.get_logger(__name__)

CONFIRM_PATH = "/auth/confirm"
FORGOT_PATH = "/auth/forgot"
RESET_PATH = "/auth/reset"


@dataclass(frozen=True, slots=True)
class _Letter:
    path: str
    token_purpose: TokenPurpose | None = None
    token_ttl: timedelta | None = None


LETTERS: dict[EmailPurpose, _Letter] = {
    EmailPurpose.EMAIL_CONFIRM: _Letter(
        CONFIRM_PATH, TokenPurpose.EMAIL_CONFIRM, EMAIL_CONFIRM_TOKEN_TTL
    ),
    EmailPurpose.ALREADY_REGISTERED: _Letter(FORGOT_PATH),
    EmailPurpose.PASSWORD_RESET: _Letter(
        RESET_PATH, TokenPurpose.PASSWORD_RESET, PASSWORD_RESET_TOKEN_TTL
    ),
}


class MailDeliveryService:
    def __init__(
        self,
        uow: UnitOfWork,
        tokens: OneTimeTokenStore,
        mailer: Mailer,
        public_base_url: str,
        batch: int,
        lease: timedelta,
    ) -> None:
        self._uow = uow
        self._tokens = tokens
        self._mailer = mailer
        self._public_base_url = public_base_url
        self._batch = batch
        self._lease = lease

    async def deliver_batch(self) -> int:
        jobs = await self._claim()
        for job in jobs:
            await self._deliver(job)
        return len(jobs)

    async def _claim(self) -> list[EmailJobDTO]:
        async with self._uow:
            jobs = await self._uow.email_jobs.claim(batch=self._batch, lease=self._lease)
            await self._uow.commit()
        return jobs

    async def _deliver(self, job: EmailJobDTO) -> None:
        if job.attempts > MAIL_MAX_ATTEMPTS:
            await self._fail(job, "attempts_exhausted")
            return
        letter = LETTERS.get(job.purpose)
        if letter is None:
            await self._fail(job, "unsupported_purpose")
            return
        async with self._uow:
            user = await self._uow.users.get(job.user_id)
        if user is None:
            await self._complete(job, "user_gone")
            return
        if job.purpose == EmailPurpose.EMAIL_CONFIRM and user.email_verified_at is not None:
            await self._complete(job, "already_confirmed")
            return
        try:
            link = await self._link(letter, user)
            await self._mailer.send(
                recipient=user.email,
                recipient_name=user.display_name,
                purpose=job.purpose,
                link=link,
            )
        except MailDeliveryPermanentError as exc:
            await self._fail(job, f"permanent: {exc}")
        except (MailDeliveryTemporaryError, DependencyUnavailableError) as exc:
            await self._retry_or_fail(job, f"temporary: {exc}")
        except Exception:
            logger.exception("mail.unexpected_error", job_id=str(job.id), purpose=job.purpose.value)
            await self._retry_or_fail(job, "unexpected")
        else:
            await self._complete(job, None)

    async def _link(self, letter: _Letter, user: UserDTO) -> str:
        url = self._public_base_url + letter.path
        if letter.token_purpose is None or letter.token_ttl is None:
            return url
        token = await self._tokens.issue(
            purpose=letter.token_purpose,
            user_id=user.id,
            ttl=letter.token_ttl,
            credentials_version=user.credentials_version,
        )
        return f"{url}#token={token}"

    async def _complete(self, job: EmailJobDTO, skipped: str | None) -> None:
        async with self._uow:
            await self._uow.email_jobs.complete(job_id=job.id)
            await self._uow.commit()
        if skipped is None:
            logger.info("mail.sent", **_fields(job))
        else:
            logger.info("mail.skipped", reason=skipped, **_fields(job))

    async def _retry_or_fail(self, job: EmailJobDTO, error: str) -> None:
        if job.attempts >= MAIL_MAX_ATTEMPTS:
            await self._fail(job, error)
            return
        delay = retry_delay(job.attempts)
        async with self._uow:
            await self._uow.email_jobs.retry(job_id=job.id, delay=delay, error=error)
            await self._uow.commit()
        logger.warning(
            "mail.retry", error=error, delay_seconds=delay.total_seconds(), **_fields(job)
        )

    async def _fail(self, job: EmailJobDTO, error: str) -> None:
        async with self._uow:
            await self._uow.email_jobs.fail(job_id=job.id, error=error)
            await self._uow.commit()
        logger.error("mail.failed", error=error, **_fields(job))


def _fields(job: EmailJobDTO) -> dict[str, object]:
    return {
        "job_id": str(job.id),
        "user_id": str(job.user_id),
        "purpose": job.purpose.value,
        "attempts": job.attempts,
    }
