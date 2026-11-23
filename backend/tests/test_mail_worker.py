import asyncio
import os
import signal
import sys
import time
from collections.abc import AsyncIterator
from datetime import timedelta
from pathlib import Path

import pytest
from smtp_stub import StubSmtp
from sqlalchemy import func, select, text, update
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.core.db import dispose_engine, get_engine, get_session_factory
from app.modules.identity.domain.enums import EmailJobStatus, EmailPurpose
from app.modules.identity.infrastructure.models import EmailJob
from app.modules.identity.infrastructure.repositories import (
    SqlEmailJobRepository,
    SqlUserRepository,
)
from app.workers.mailer import _check_lease

BACKEND = Path(__file__).resolve().parents[1]


@pytest.fixture
async def factory(
    migrated_schema: None, _point_redis_at_container: None
) -> AsyncIterator[async_sessionmaker[AsyncSession]]:
    get_engine.cache_clear()
    get_session_factory.cache_clear()

    yield async_sessionmaker(get_engine(), expire_on_commit=False)

    async with get_engine().begin() as connection:
        await connection.execute(text("TRUNCATE users CASCADE"))
    await dispose_engine()


@pytest.fixture
async def smtp() -> AsyncIterator[tuple[StubSmtp, int]]:
    stub = StubSmtp()
    server = await asyncio.start_server(stub.handle, "127.0.0.1", 0)

    yield stub, server.sockets[0].getsockname()[1]

    server.close()
    await server.wait_closed()


async def _spawn(port: int, **env: str) -> asyncio.subprocess.Process:
    return await asyncio.create_subprocess_exec(
        sys.executable,
        "-m",
        "app.workers.mailer",
        cwd=BACKEND,
        env={
            **os.environ,
            "MAIL__HOST": "127.0.0.1",
            "MAIL__PORT": str(port),
            "MAIL__TLS": "none",
            "MAIL_WORKER__POLL_INTERVAL_SECONDS": "0.2",
            **env,
        },
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT,
    )


async def _finish(
    process: asyncio.subprocess.Process, sig: int | None = None
) -> tuple[int | None, str]:
    if sig is not None:
        process.send_signal(sig)
    output, _ = await asyncio.wait_for(process.communicate(), timeout=15)
    return process.returncode, output.decode()


async def _queue(factory: async_sessionmaker[AsyncSession], **values: object) -> None:
    async with factory() as session:
        user_id = await SqlUserRepository(session).create(
            f"cook-{time.monotonic_ns()}@example.org", "Cook"
        )
        assert user_id is not None
        await SqlEmailJobRepository(session).enqueue(EmailPurpose.EMAIL_CONFIRM, user_id)
        if values:
            await session.execute(
                update(EmailJob).where(EmailJob.user_id == user_id).values(**values)
            )
        await session.commit()


async def _jobs(factory: async_sessionmaker[AsyncSession]) -> int:
    async with factory() as session:
        count = await session.scalar(select(func.count()).select_from(EmailJob))
    return int(count or 0)


async def _until_empty(factory: async_sessionmaker[AsyncSession], seconds: float) -> bool:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if await _jobs(factory) == 0:
            return True
        await asyncio.sleep(0.1)
    return False


def test_lease_longer_than_a_slow_batch_is_accepted() -> None:
    _check_lease(batch_size=10, lease_seconds=101)


@pytest.mark.parametrize(("batch_size", "lease_seconds"), [(10, 100), (10, 60), (30, 299)])
def test_lease_shorter_than_a_slow_batch_is_refused(batch_size: int, lease_seconds: float) -> None:
    with pytest.raises(ValueError, match="MAIL_WORKER__LEASE_SECONDS"):
        _check_lease(batch_size=batch_size, lease_seconds=lease_seconds)


async def test_worker_sends_queued_letters_and_stops_cleanly(
    factory: async_sessionmaker[AsyncSession], smtp: tuple[StubSmtp, int]
) -> None:
    stub, port = smtp
    await _queue(factory)
    await _queue(factory)
    process = await _spawn(port)

    emptied = await _until_empty(factory, 10)
    code, output = await _finish(process, signal.SIGINT)

    assert emptied
    assert len(stub.messages) == 2
    assert code == 0
    assert "mailer.started" in output
    assert "mailer.stopped" in output
    assert "Traceback" not in output
    assert "@example.org" not in output


async def test_idle_worker_stops_at_once_on_sigterm(
    factory: async_sessionmaker[AsyncSession], smtp: tuple[StubSmtp, int]
) -> None:
    _, port = smtp
    process = await _spawn(port, MAIL_WORKER__POLL_INTERVAL_SECONDS="30")
    await asyncio.sleep(2)
    started = time.monotonic()

    code, output = await _finish(process, signal.SIGTERM)

    assert code == 0
    assert time.monotonic() - started < 3
    assert "mailer.stopped" in output


async def test_worker_refuses_to_start_with_a_short_lease(
    factory: async_sessionmaker[AsyncSession], smtp: tuple[StubSmtp, int]
) -> None:
    _, port = smtp
    await _queue(factory)

    code, output = await _finish(await _spawn(port, MAIL_WORKER__LEASE_SECONDS="50"))

    assert code == 1
    assert "MAIL_WORKER__LEASE_SECONDS" in output
    assert await _jobs(factory) == 1


async def test_worker_survives_an_unreachable_database(
    factory: async_sessionmaker[AsyncSession], smtp: tuple[StubSmtp, int]
) -> None:
    _, port = smtp
    process = await _spawn(port, DB__PORT="1")
    await asyncio.sleep(3)
    alive = process.returncode is None

    code, output = await _finish(process, signal.SIGTERM)

    assert alive
    assert output.count("mailer.batch_failed") >= 2
    assert code == 0


async def test_worker_cleans_expired_rows_on_start(
    factory: async_sessionmaker[AsyncSession], smtp: tuple[StubSmtp, int]
) -> None:
    _, port = smtp
    await _queue(
        factory,
        status=EmailJobStatus.FAILED,
        updated_at=func.now() - timedelta(days=31),
    )
    await _queue(
        factory,
        status=EmailJobStatus.FAILED,
        updated_at=func.now() - timedelta(days=5),
    )
    process = await _spawn(port)
    await asyncio.sleep(2)

    code, output = await _finish(process, signal.SIGTERM)

    assert "mailer.cleanup_done" in output
    assert await _jobs(factory) == 1
    assert code == 0
