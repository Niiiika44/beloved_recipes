import asyncio
import signal
import time
from contextlib import suppress
from datetime import timedelta

import structlog

from app.core.config import Settings, get_settings
from app.core.db import dispose_engine, get_session_factory
from app.core.logging import configure_logging
from app.core.redis import close_redis, get_redis
from app.modules.identity.infrastructure.redis_one_time_token_store import RedisOneTimeTokenStore
from app.modules.identity.infrastructure.smtp_mailer import SMTP_TIMEOUT_SECONDS, SmtpMailer
from app.modules.identity.infrastructure.uow import SqlAlchemyUnitOfWork
from app.modules.identity.service.mail_delivery import MailDeliveryService
from app.modules.identity.service.maintenance import purge_expired

logger = structlog.get_logger(__name__)

CLEANUP_INTERVAL_SECONDS = 3600.0


def _check_lease(batch_size: int, lease_seconds: float) -> None:
    if lease_seconds <= batch_size * SMTP_TIMEOUT_SECONDS:
        raise ValueError(
            f"MAIL_WORKER__LEASE_SECONDS={lease_seconds} must exceed "
            f"batch_size × SMTP timeout = {batch_size * SMTP_TIMEOUT_SECONDS:.0f}"
        )


def _build_service(settings: Settings) -> MailDeliveryService:
    return MailDeliveryService(
        uow=SqlAlchemyUnitOfWork(get_session_factory()),
        tokens=RedisOneTimeTokenStore(
            client=get_redis(),
            operation_timeout_seconds=settings.token.operation_timeout_seconds,
        ),
        mailer=SmtpMailer(settings.mail),
        public_base_url=settings.app.public_base_url,
        batch=settings.mail_worker.batch_size,
        lease=timedelta(seconds=settings.mail_worker.lease_seconds),
    )


async def _cleanup() -> None:
    try:
        await purge_expired(SqlAlchemyUnitOfWork(get_session_factory()))
    except Exception:
        logger.exception("mailer.cleanup_failed")
    else:
        logger.info("mailer.cleanup_done")


async def _wait(stop: asyncio.Event, seconds: float) -> None:
    with suppress(TimeoutError):
        await asyncio.wait_for(stop.wait(), timeout=seconds)


async def run() -> None:
    configure_logging()
    settings = get_settings()
    _check_lease(settings.mail_worker.batch_size, settings.mail_worker.lease_seconds)
    service = _build_service(settings)

    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, stop.set)

    logger.info("mailer.started")
    last_cleanup: float | None = None
    try:
        while not stop.is_set():
            now = time.monotonic()
            if last_cleanup is None or now - last_cleanup >= CLEANUP_INTERVAL_SECONDS:
                await _cleanup()
                last_cleanup = now
            try:
                taken = await service.deliver_batch()
            except Exception:
                logger.exception("mailer.batch_failed")
                taken = 0
            if taken == 0:
                await _wait(stop, settings.mail_worker.poll_interval_seconds)
    finally:
        await dispose_engine()
        await close_redis()
        logger.info("mailer.stopped")


if __name__ == "__main__":
    asyncio.run(run())
