import uuid
from collections.abc import AsyncIterator
from typing import Any

import pytest
from sqlalchemy import event, text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from sqlalchemy.pool import QueuePool

from app.core.db import dispose_engine, get_engine, get_session_factory
from app.modules.identity.infrastructure.models import User
from app.modules.identity.infrastructure.uow import SqlAlchemyUnitOfWork
from app.modules.identity.service.ports import UnitOfWork


class Transactions:
    def __init__(self) -> None:
        self.commits = 0
        self.rollbacks = 0

    def on_commit(self, *args: Any) -> None:
        self.commits += 1

    def on_rollback(self, *args: Any) -> None:
        self.rollbacks += 1


@pytest.fixture
async def factory(migrated_schema: None) -> AsyncIterator[async_sessionmaker[AsyncSession]]:
    get_engine.cache_clear()
    get_session_factory.cache_clear()

    yield async_sessionmaker(get_engine(), expire_on_commit=False, close_resets_only=False)

    async with get_engine().begin() as connection:
        await connection.execute(text("TRUNCATE users, workspaces, memberships, invites CASCADE"))
    await dispose_engine()


@pytest.fixture
async def user_id(factory: async_sessionmaker[AsyncSession]) -> uuid.UUID:
    suffix = uuid.uuid4().hex[:8]
    async with factory() as session:
        user = User(
            email=f"cook-{suffix}@example.com",
            google_sub=f"sub-{suffix}",
            display_name=f"Cook {suffix}",
        )
        session.add(user)
        await session.commit()
        return user.id


@pytest.fixture
def transactions(factory: async_sessionmaker[AsyncSession]) -> Transactions:
    tracker = Transactions()
    engine = get_engine().sync_engine
    event.listen(engine, "commit", tracker.on_commit)
    event.listen(engine, "rollback", tracker.on_rollback)
    return tracker


def _checked_out() -> int:
    pool = get_engine().pool
    assert isinstance(pool, QueuePool)
    return pool.checkedout()


async def _fail_inside(uow: SqlAlchemyUnitOfWork, user_id: uuid.UUID, error: Exception) -> None:
    async with uow:
        await uow.users.get(user_id)
        raise error


def test_satisfies_the_port(factory: async_sessionmaker[AsyncSession]) -> None:
    uow: UnitOfWork = SqlAlchemyUnitOfWork(factory)

    assert isinstance(uow, SqlAlchemyUnitOfWork)


async def test_reads_through_its_repository(
    factory: async_sessionmaker[AsyncSession], user_id: uuid.UUID
) -> None:
    async with SqlAlchemyUnitOfWork(factory) as uow:
        found = await uow.users.get(user_id)

    assert found is not None
    assert found.id == user_id


async def test_can_be_entered_twice_in_a_row(
    factory: async_sessionmaker[AsyncSession], user_id: uuid.UUID
) -> None:
    uow = SqlAlchemyUnitOfWork(factory)

    async with uow:
        first = await uow.users.get(user_id)
    async with uow:
        second = await uow.users.get(user_id)

    assert first is not None
    assert second is not None
    assert first == second


async def test_connection_returns_to_pool_after_block(
    factory: async_sessionmaker[AsyncSession], user_id: uuid.UUID
) -> None:
    async with SqlAlchemyUnitOfWork(factory) as uow:
        await uow.users.get(user_id)
        assert _checked_out() == 1

    assert _checked_out() == 0


async def test_connection_returns_to_pool_after_failure(
    factory: async_sessionmaker[AsyncSession], user_id: uuid.UUID
) -> None:
    with pytest.raises(RuntimeError):
        await _fail_inside(SqlAlchemyUnitOfWork(factory), user_id, RuntimeError("failed"))

    assert _checked_out() == 0


async def test_exception_leaves_the_block_unchanged(
    factory: async_sessionmaker[AsyncSession], user_id: uuid.UUID
) -> None:
    error = RuntimeError("scenario failed")

    with pytest.raises(RuntimeError) as caught:
        await _fail_inside(SqlAlchemyUnitOfWork(factory), user_id, error)

    assert caught.value is error


async def test_commit_reaches_the_database(
    factory: async_sessionmaker[AsyncSession], user_id: uuid.UUID, transactions: Transactions
) -> None:
    async with SqlAlchemyUnitOfWork(factory) as uow:
        await uow.users.get(user_id)
        await uow.commit()

    assert transactions.commits == 1
    assert transactions.rollbacks == 0


async def test_block_without_commit_is_rolled_back(
    factory: async_sessionmaker[AsyncSession], user_id: uuid.UUID, transactions: Transactions
) -> None:
    async with SqlAlchemyUnitOfWork(factory) as uow:
        await uow.users.get(user_id)

    assert transactions.commits == 0
    assert transactions.rollbacks >= 1


async def test_failed_block_is_rolled_back(
    factory: async_sessionmaker[AsyncSession], user_id: uuid.UUID, transactions: Transactions
) -> None:
    with pytest.raises(RuntimeError):
        await _fail_inside(SqlAlchemyUnitOfWork(factory), user_id, RuntimeError("failed"))

    assert transactions.commits == 0
    assert transactions.rollbacks >= 1


async def test_commit_of_one_entry_does_not_carry_over_to_the_next(
    factory: async_sessionmaker[AsyncSession], user_id: uuid.UUID, transactions: Transactions
) -> None:
    uow = SqlAlchemyUnitOfWork(factory)
    async with uow:
        await uow.users.get(user_id)
        await uow.commit()

    async with uow:
        await uow.users.get(user_id)

    assert transactions.commits == 1
    assert transactions.rollbacks >= 1
