from app.modules.identity.domain.mail import FAILED_MAIL_RETENTION
from app.modules.identity.domain.nicknames import NICKNAME_QUARANTINE
from app.modules.identity.service.ports import UnitOfWork


async def purge_expired(uow: UnitOfWork) -> None:
    async with uow:
        await uow.email_jobs.purge_failed(older_than=FAILED_MAIL_RETENTION)
        await uow.nicknames.purge_released(older_than=NICKNAME_QUARANTINE)
        await uow.commit()
