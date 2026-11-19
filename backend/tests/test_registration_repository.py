import asyncio
import uuid
from collections.abc import AsyncIterator
from datetime import datetime
from typing import Any

import pytest
from sqlalchemy import func, select, text, update
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.core.db import dispose_engine, get_engine, get_session_factory
from app.modules.identity.domain.enums import EmailJobStatus, EmailPurpose
from app.modules.identity.infrastructure.models import EmailJob, PasswordCredential, User
from app.modules.identity.infrastructure.repositories import (
    SqlEmailJobRepository,
    SqlPasswordRepository,
    SqlUserRepository,
)
from app.modules.identity.infrastructure.uow import SqlAlchemyUnitOfWork
from app.modules.identity.service.dto import UserDTO


@pytest.fixture
async def factory(migrated_schema: None) -> AsyncIterator[async_sessionmaker[AsyncSession]]:
    get_engine.cache_clear()
    get_session_factory.cache_clear()

    yield async_sessionmaker(get_engine(), expire_on_commit=False)

    async with get_engine().begin() as connection:
        await connection.execute(text("TRUNCATE users CASCADE"))
    await dispose_engine()


async def _committed_user(factory: async_sessionmaker[AsyncSession], email: str) -> uuid.UUID:
    async with factory() as session:
        user_id = await SqlUserRepository(session).create(email, "Cook")
        await session.commit()
    assert user_id is not None
    return user_id


async def _users(factory: async_sessionmaker[AsyncSession]) -> list[Any]:
    async with factory() as session:
        rows = await session.execute(
            select(
                User.email,
                User.display_name,
                User.nickname,
                User.email_verified_at,
                User.avatar_url,
            )
        )
        return list(rows.all())


async def _hashes(
    factory: async_sessionmaker[AsyncSession],
) -> dict[uuid.UUID, tuple[str, datetime]]:
    async with factory() as session:
        rows = await session.execute(select(PasswordCredential))
        return {row.user_id: (row.password_hash, row.updated_at) for row in rows.scalars()}


async def _jobs(factory: async_sessionmaker[AsyncSession]) -> list[tuple[uuid.UUID, str, str]]:
    async with factory() as session:
        rows = await session.execute(select(EmailJob.user_id, EmailJob.purpose, EmailJob.status))
        return sorted((row.user_id, str(row.purpose), str(row.status)) for row in rows)


async def _waiting_for_a_lock(factory: async_sessionmaker[AsyncSession]) -> None:
    async with factory() as session:
        while True:
            waiting = await session.scalar(
                text("SELECT count(*) FROM pg_stat_activity WHERE wait_event_type = 'Lock'")
            )
            await session.rollback()
            if waiting:
                return
            await asyncio.sleep(0.02)


async def test_create_inserts_user_as_entered(factory: async_sessionmaker[AsyncSession]) -> None:
    async with factory() as session:
        user_id = await SqlUserRepository(session).create("Anna@Example.org", "Anna")
        await session.commit()

    assert isinstance(user_id, uuid.UUID)
    assert await _users(factory) == [("Anna@Example.org", "Anna", None, None, None)]


@pytest.mark.parametrize("email", ["anna@example.org", "ANNA@EXAMPLE.ORG", "Anna@example.Org"])
async def test_create_on_taken_email_returns_none(
    factory: async_sessionmaker[AsyncSession], email: str
) -> None:
    await _committed_user(factory, "anna@example.org")

    async with factory() as session:
        assert await SqlUserRepository(session).create(email, "Other") is None
        await session.commit()

    assert len(await _users(factory)) == 1


async def test_taken_email_keeps_the_transaction_usable(
    factory: async_sessionmaker[AsyncSession],
) -> None:
    existing = await _committed_user(factory, "anna@example.org")

    async with factory() as session:
        users = SqlUserRepository(session)
        assert await users.create("anna@example.org", "Other") is None
        found = await users.find_by_email("anna@example.org")
        await SqlEmailJobRepository(session).enqueue(EmailPurpose.ALREADY_REGISTERED, existing)
        await session.commit()

    assert found is not None
    assert found.id == existing
    assert await _jobs(factory) == [(existing, "already_registered", "pending")]


async def test_create_waits_for_a_parallel_registration_that_commits(
    factory: async_sessionmaker[AsyncSession],
) -> None:
    async with factory() as first, factory() as second:
        winner = await SqlUserRepository(first).create("anna@example.org", "First")
        losing = asyncio.create_task(SqlUserRepository(second).create("ANNA@example.org", "Second"))
        await asyncio.wait_for(_waiting_for_a_lock(factory), timeout=5)

        assert losing.done() is False

        await first.commit()
        loser = await asyncio.wait_for(losing, timeout=5)
        found = await SqlUserRepository(second).find_by_email("anna@example.org")
        await second.commit()

    assert winner is not None
    assert loser is None
    assert found is not None
    assert found.id == winner


async def test_create_succeeds_when_the_parallel_registration_rolls_back(
    factory: async_sessionmaker[AsyncSession],
) -> None:
    async with factory() as first, factory() as second:
        await SqlUserRepository(first).create("anna@example.org", "First")
        pending = asyncio.create_task(
            SqlUserRepository(second).create("anna@example.org", "Second")
        )
        await asyncio.wait_for(_waiting_for_a_lock(factory), timeout=5)
        await first.rollback()
        user_id = await asyncio.wait_for(pending, timeout=5)
        await second.commit()

    assert user_id is not None
    assert await _users(factory) == [("anna@example.org", "Second", None, None, None)]


async def test_create_never_commits(factory: async_sessionmaker[AsyncSession]) -> None:
    async with factory() as session:
        await SqlUserRepository(session).create("anna@example.org", "Anna")
        await session.rollback()

    assert await _users(factory) == []


@pytest.mark.parametrize("asked", ["anna@example.org", "ANNA@EXAMPLE.ORG"])
async def test_find_by_email_ignores_case(
    factory: async_sessionmaker[AsyncSession], asked: str
) -> None:
    user_id = await _committed_user(factory, "Anna@Example.org")

    async with factory() as session:
        found = await SqlUserRepository(session).find_by_email(asked)

    assert type(found) is UserDTO
    assert found.id == user_id
    assert found.email == "Anna@Example.org"
    assert found.nickname is None


async def test_find_by_email_of_unknown_address_returns_none(
    factory: async_sessionmaker[AsyncSession],
) -> None:
    await _committed_user(factory, "anna@example.org")

    async with factory() as session:
        assert await SqlUserRepository(session).find_by_email("boris@example.org") is None


async def test_set_hash_stores_the_hash(factory: async_sessionmaker[AsyncSession]) -> None:
    user_id = await _committed_user(factory, "anna@example.org")

    async with factory() as session:
        await SqlPasswordRepository(session).set_hash(user_id, "$argon2id$first")
        await session.commit()

    assert (await _hashes(factory))[user_id][0] == "$argon2id$first"


async def test_set_hash_replaces_the_hash_and_moves_updated_at(
    factory: async_sessionmaker[AsyncSession],
) -> None:
    user_id = await _committed_user(factory, "anna@example.org")
    async with factory() as session:
        await SqlPasswordRepository(session).set_hash(user_id, "$argon2id$first")
        await session.commit()
    first_updated = (await _hashes(factory))[user_id][1]

    async with factory() as session:
        await SqlPasswordRepository(session).set_hash(user_id, "$argon2id$second")
        transaction_time = await session.scalar(text("SELECT now()"))
        await session.commit()

    password_hash, updated_at = (await _hashes(factory))[user_id]
    assert password_hash == "$argon2id$second"
    assert updated_at == transaction_time
    assert updated_at > first_updated


async def test_set_hash_touches_only_the_given_user(
    factory: async_sessionmaker[AsyncSession],
) -> None:
    neighbour = await _committed_user(factory, "boris@example.org")
    user_id = await _committed_user(factory, "anna@example.org")
    async with factory() as session:
        await SqlPasswordRepository(session).set_hash(neighbour, "$argon2id$neighbour")
        await SqlPasswordRepository(session).set_hash(user_id, "$argon2id$own")
        await session.commit()

    hashes = await _hashes(factory)
    assert hashes[neighbour][0] == "$argon2id$neighbour"
    assert hashes[user_id][0] == "$argon2id$own"


async def test_set_hash_never_commits(factory: async_sessionmaker[AsyncSession]) -> None:
    user_id = await _committed_user(factory, "anna@example.org")

    async with factory() as session:
        await SqlPasswordRepository(session).set_hash(user_id, "$argon2id$first")
        await session.rollback()

    assert await _hashes(factory) == {}


async def test_enqueue_creates_a_pending_job_ready_now(
    factory: async_sessionmaker[AsyncSession],
) -> None:
    user_id = await _committed_user(factory, "anna@example.org")

    async with factory() as session:
        await SqlEmailJobRepository(session).enqueue(EmailPurpose.EMAIL_CONFIRM, user_id)
        transaction_time = await session.scalar(text("SELECT now()"))
        await session.commit()

    async with factory() as session:
        job = (await session.execute(select(EmailJob))).scalar_one()
    assert job.user_id == user_id
    assert job.purpose == EmailPurpose.EMAIL_CONFIRM
    assert job.status == EmailJobStatus.PENDING
    assert job.attempts == 0
    assert job.available_at == transaction_time
    assert job.locked_until is None
    assert job.last_error is None


async def test_enqueue_skips_a_job_already_waiting(
    factory: async_sessionmaker[AsyncSession],
) -> None:
    user_id = await _committed_user(factory, "anna@example.org")

    async with factory() as session:
        jobs = SqlEmailJobRepository(session)
        await jobs.enqueue(EmailPurpose.ALREADY_REGISTERED, user_id)
        await jobs.enqueue(EmailPurpose.ALREADY_REGISTERED, user_id)
        await jobs.enqueue(EmailPurpose.EMAIL_CONFIRM, user_id)
        await session.commit()

    assert await _jobs(factory) == sorted(
        [(user_id, "already_registered", "pending"), (user_id, "email_confirm", "pending")]
    )


async def test_enqueue_after_a_failed_job_creates_a_new_one(
    factory: async_sessionmaker[AsyncSession],
) -> None:
    user_id = await _committed_user(factory, "anna@example.org")
    async with factory() as session:
        await SqlEmailJobRepository(session).enqueue(EmailPurpose.EMAIL_CONFIRM, user_id)
        await session.execute(update(EmailJob).values(status=EmailJobStatus.FAILED))
        await session.commit()

    async with factory() as session:
        await SqlEmailJobRepository(session).enqueue(EmailPurpose.EMAIL_CONFIRM, user_id)
        await session.commit()

    assert await _jobs(factory) == sorted(
        [(user_id, "email_confirm", "failed"), (user_id, "email_confirm", "pending")]
    )


async def test_enqueue_keeps_working_after_many_calls_on_one_connection(
    factory: async_sessionmaker[AsyncSession],
) -> None:
    user_id = await _committed_user(factory, "anna@example.org")

    async with factory() as session:
        jobs = SqlEmailJobRepository(session)
        for _ in range(12):
            await jobs.enqueue(EmailPurpose.ALREADY_REGISTERED, user_id)
        await session.commit()

    assert await _jobs(factory) == [(user_id, "already_registered", "pending")]


async def test_enqueue_never_commits(factory: async_sessionmaker[AsyncSession]) -> None:
    user_id = await _committed_user(factory, "anna@example.org")

    async with factory() as session:
        await SqlEmailJobRepository(session).enqueue(EmailPurpose.EMAIL_CONFIRM, user_id)
        await session.rollback()

    assert await _jobs(factory) == []


async def test_registration_writes_share_one_transaction(
    factory: async_sessionmaker[AsyncSession],
) -> None:
    async with SqlAlchemyUnitOfWork(factory) as uow:
        user_id = await uow.users.create("anna@example.org", "Anna")
        assert user_id is not None
        await uow.passwords.set_hash(user_id, "$argon2id$hash")
        await uow.email_jobs.enqueue(EmailPurpose.EMAIL_CONFIRM, user_id)

    async with factory() as session:
        counts = [
            await session.scalar(select(func.count()).select_from(table))
            for table in (User, PasswordCredential, EmailJob)
        ]
    assert counts == [0, 0, 0]
