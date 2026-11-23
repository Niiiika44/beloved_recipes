import asyncio
import uuid
from collections.abc import AsyncIterator
from datetime import datetime, timedelta
from typing import Any

import pytest
from sqlalchemy import func, select, text, update
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.core.db import dispose_engine, get_engine, get_session_factory
from app.modules.identity.domain.enums import EmailJobStatus, EmailPurpose
from app.modules.identity.infrastructure.models import EmailJob, ReleasedNickname, User
from app.modules.identity.infrastructure.repositories import (
    SqlEmailJobRepository,
    SqlNicknameRepository,
    SqlUserRepository,
)
from app.modules.identity.service.dto import EmailJobDTO

LEASE = timedelta(minutes=5)


@pytest.fixture
async def factory(migrated_schema: None) -> AsyncIterator[async_sessionmaker[AsyncSession]]:
    get_engine.cache_clear()
    get_session_factory.cache_clear()

    yield async_sessionmaker(get_engine(), expire_on_commit=False)

    async with get_engine().begin() as connection:
        await connection.execute(text("TRUNCATE users, released_nicknames CASCADE"))
    await dispose_engine()


async def _user(factory: async_sessionmaker[AsyncSession], email: str = "") -> uuid.UUID:
    async with factory() as session:
        user_id = await SqlUserRepository(session).create(
            email or f"cook-{uuid.uuid4().hex[:8]}@example.org", "Cook"
        )
        await session.commit()
    assert user_id is not None
    return user_id


async def _job(
    factory: async_sessionmaker[AsyncSession],
    purpose: EmailPurpose = EmailPurpose.EMAIL_CONFIRM,
    **values: Any,
) -> uuid.UUID:
    user_id = await _user(factory)
    async with factory() as session:
        await SqlEmailJobRepository(session).enqueue(purpose, user_id)
        if values:
            await session.execute(
                update(EmailJob).where(EmailJob.user_id == user_id).values(**values)
            )
        await session.commit()
        job_id = await session.scalar(select(EmailJob.id).where(EmailJob.user_id == user_id))
    assert job_id is not None
    return job_id


async def _claim(
    factory: async_sessionmaker[AsyncSession], batch: int = 10, lease: timedelta = LEASE
) -> list[EmailJobDTO]:
    async with factory() as session:
        jobs = await SqlEmailJobRepository(session).claim(batch, lease)
        await session.commit()
    return jobs


async def _row(factory: async_sessionmaker[AsyncSession], job_id: uuid.UUID) -> Any:
    async with factory() as session:
        return (
            await session.execute(
                select(
                    EmailJob.status,
                    EmailJob.attempts,
                    EmailJob.locked_until,
                    EmailJob.available_at,
                    EmailJob.last_error,
                    EmailJob.updated_at,
                    func.now(),
                ).where(EmailJob.id == job_id)
            )
        ).one_or_none()


def _ago(minutes: int) -> Any:
    return func.now() - timedelta(minutes=minutes)


def _ahead(minutes: int) -> Any:
    return func.now() + timedelta(minutes=minutes)


async def test_claim_takes_a_fresh_pending_job(factory: async_sessionmaker[AsyncSession]) -> None:
    job_id = await _job(factory)

    [job] = await _claim(factory)

    assert job.id == job_id
    assert job.purpose == EmailPurpose.EMAIL_CONFIRM
    assert job.attempts == 1
    assert type(job) is EmailJobDTO


async def test_claim_leases_the_job_and_counts_the_attempt(
    factory: async_sessionmaker[AsyncSession],
) -> None:
    job_id = await _job(factory)

    async with factory() as session:
        await SqlEmailJobRepository(session).claim(10, LEASE)
        claimed_at = await session.scalar(text("SELECT now()"))
        await session.commit()

    row = await _row(factory, job_id)
    assert row.status == EmailJobStatus.PENDING
    assert row.attempts == 1
    assert row.locked_until == claimed_at + LEASE
    assert row.updated_at == claimed_at


@pytest.mark.parametrize(
    "values",
    [
        {"status": EmailJobStatus.FAILED},
        {"available_at": _ahead(10)},
        {"locked_until": _ahead(1)},
    ],
    ids=["failed", "postponed", "leased_by_another_worker"],
)
async def test_claim_skips_jobs_that_are_not_due(
    factory: async_sessionmaker[AsyncSession], values: dict[str, Any]
) -> None:
    await _job(factory, **values)

    assert await _claim(factory) == []


async def test_claim_takes_a_job_whose_lease_expired(
    factory: async_sessionmaker[AsyncSession],
) -> None:
    job_id = await _job(factory, locked_until=_ago(1), attempts=1)

    [job] = await _claim(factory)

    assert job.id == job_id
    assert job.attempts == 2


async def test_claim_takes_the_oldest_first_up_to_the_batch(
    factory: async_sessionmaker[AsyncSession],
) -> None:
    newest = await _job(factory, available_at=_ago(1))
    oldest = await _job(factory, available_at=_ago(30))
    middle = await _job(factory, available_at=_ago(10))

    first = await _claim(factory, batch=2)
    second = await _claim(factory, batch=2)

    assert {job.id for job in first} == {oldest, middle}
    assert [job.id for job in second] == [newest]


async def test_parallel_claims_never_share_a_job(
    factory: async_sessionmaker[AsyncSession],
) -> None:
    for _ in range(6):
        await _job(factory)

    batches = await asyncio.gather(*(_claim(factory, batch=2) for _ in range(5)))

    claimed = [job.id for batch in batches for job in batch]
    assert len(claimed) == 6
    assert len(set(claimed)) == 6


async def test_claim_keeps_working_after_many_calls_on_one_connection(
    factory: async_sessionmaker[AsyncSession],
) -> None:
    for _ in range(3):
        await _job(factory)

    async with factory() as session:
        jobs = SqlEmailJobRepository(session)
        results = [await jobs.claim(1, LEASE) for _ in range(12)]
        await session.commit()

    assert [len(batch) for batch in results] == [1, 1, 1] + [0] * 9


async def test_claim_never_commits(factory: async_sessionmaker[AsyncSession]) -> None:
    job_id = await _job(factory)

    async with factory() as session:
        await SqlEmailJobRepository(session).claim(10, LEASE)
        await session.rollback()

    row = await _row(factory, job_id)
    assert row.attempts == 0
    assert row.locked_until is None


async def test_complete_deletes_the_job(factory: async_sessionmaker[AsyncSession]) -> None:
    job_id = await _job(factory)

    async with factory() as session:
        await SqlEmailJobRepository(session).complete(job_id)
        await session.commit()

    assert await _row(factory, job_id) is None


async def test_retry_releases_and_postpones_from_now(
    factory: async_sessionmaker[AsyncSession],
) -> None:
    job_id = await _job(factory, available_at=_ago(180), locked_until=_ahead(5), attempts=1)

    async with factory() as session:
        await SqlEmailJobRepository(session).retry(job_id, timedelta(seconds=30), "temporary")
        retried_at = await session.scalar(text("SELECT now()"))
        await session.commit()

    row = await _row(factory, job_id)
    assert row.status == EmailJobStatus.PENDING
    assert row.locked_until is None
    assert row.available_at == retried_at + timedelta(seconds=30)
    assert row.last_error == "temporary"
    assert row.attempts == 1
    assert await _claim(factory) == []


async def test_fail_marks_failed_and_releases(factory: async_sessionmaker[AsyncSession]) -> None:
    job_id = await _job(factory, locked_until=_ahead(5), attempts=8)

    async with factory() as session:
        await SqlEmailJobRepository(session).fail(job_id, "permanent: recipient refused")
        await session.commit()

    row = await _row(factory, job_id)
    assert row.status == EmailJobStatus.FAILED
    assert row.locked_until is None
    assert row.last_error == "permanent: recipient refused"


async def test_failed_job_does_not_block_a_new_one(
    factory: async_sessionmaker[AsyncSession],
) -> None:
    job_id = await _job(factory)
    async with factory() as session:
        jobs = SqlEmailJobRepository(session)
        await jobs.fail(job_id, "permanent")
        user_id = await session.scalar(select(EmailJob.user_id).where(EmailJob.id == job_id))
        assert user_id is not None
        await jobs.enqueue(EmailPurpose.EMAIL_CONFIRM, user_id)
        await session.commit()

    assert len(await _claim(factory)) == 1


@pytest.mark.parametrize(
    ("status", "age_days", "kept"),
    [
        (EmailJobStatus.FAILED, 31, False),
        (EmailJobStatus.FAILED, 29, True),
        (EmailJobStatus.PENDING, 90, True),
    ],
    ids=["old_failed", "young_failed", "old_pending"],
)
async def test_purge_failed_removes_only_old_failed_jobs(
    factory: async_sessionmaker[AsyncSession],
    status: EmailJobStatus,
    age_days: int,
    kept: bool,
) -> None:
    job_id = await _job(factory, status=status, updated_at=func.now() - timedelta(days=age_days))

    async with factory() as session:
        await SqlEmailJobRepository(session).purge_failed(timedelta(days=30))
        await session.commit()

    assert (await _row(factory, job_id) is not None) is kept


async def test_mark_email_verified_sets_the_moment_once(
    factory: async_sessionmaker[AsyncSession],
) -> None:
    user_id = await _user(factory)

    async with factory() as session:
        users = SqlUserRepository(session)
        await users.mark_email_verified(user_id)
        first = await session.scalar(text("SELECT now()"))
        await session.commit()
    async with factory() as session:
        await SqlUserRepository(session).mark_email_verified(user_id)
        await session.commit()

    async with factory() as session:
        found = await SqlUserRepository(session).get(user_id)
    assert found is not None
    assert found.email_verified_at == first


async def test_mark_email_verified_touches_only_the_given_user(
    factory: async_sessionmaker[AsyncSession],
) -> None:
    neighbour = await _user(factory)
    user_id = await _user(factory)

    async with factory() as session:
        await SqlUserRepository(session).mark_email_verified(user_id)
        await session.commit()

    async with factory() as session:
        verified = await session.scalar(select(User.email_verified_at).where(User.id == neighbour))
    assert verified is None


async def test_unverified_user_has_no_verification_moment(
    factory: async_sessionmaker[AsyncSession],
) -> None:
    await _user(factory, "anna@example.org")

    async with factory() as session:
        found = await SqlUserRepository(session).find_by_email("anna@example.org")

    assert found is not None
    assert found.email_verified_at is None


@pytest.mark.parametrize(("age_days", "kept"), [(31, False), (29, True)])
async def test_purge_released_removes_only_expired_quarantine(
    factory: async_sessionmaker[AsyncSession], age_days: int, kept: bool
) -> None:
    async with factory() as session:
        session.add(
            ReleasedNickname(
                nickname="anna",
                released_by=None,
                released_at=datetime.now().astimezone() - timedelta(days=age_days),
            )
        )
        await session.commit()

    async with factory() as session:
        await SqlNicknameRepository(session).purge_released(timedelta(days=30))
        await session.commit()

    async with factory() as session:
        left = await session.scalar(select(func.count()).select_from(ReleasedNickname))
    assert (left == 1) is kept
