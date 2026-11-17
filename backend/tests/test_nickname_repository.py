import asyncio
import uuid
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from typing import Any

import pytest
from sqlalchemy import event, select, text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.core.db import dispose_engine, get_engine, get_session_factory
from app.modules.identity.infrastructure.models import ReleasedNickname, User
from app.modules.identity.infrastructure.repositories import (
    NICKNAME_LOCK_SPACE,
    SqlNicknameRepository,
    SqlUserRepository,
)
from app.modules.identity.service.dto import ReleasedNicknameDTO, UserDTO

LONG_AGO = datetime(2026, 1, 1, 12, 0, tzinfo=UTC)


@pytest.fixture
async def factory(migrated_schema: None) -> AsyncIterator[async_sessionmaker[AsyncSession]]:
    get_engine.cache_clear()
    get_session_factory.cache_clear()

    yield async_sessionmaker(get_engine(), expire_on_commit=False)

    async with get_engine().begin() as connection:
        await connection.execute(text("TRUNCATE users, released_nicknames CASCADE"))
    await dispose_engine()


async def _create_user(
    factory: async_sessionmaker[AsyncSession], nickname: str | None = None
) -> uuid.UUID:
    suffix = uuid.uuid4().hex[:8]
    async with factory() as session:
        user = User(
            email=f"cook-{suffix}@example.com", display_name=f"Cook {suffix}", nickname=nickname
        )
        session.add(user)
        await session.commit()
        return user.id


async def _release(
    factory: async_sessionmaker[AsyncSession],
    nickname: str,
    released_by: uuid.UUID | None,
    released_at: datetime = LONG_AGO,
) -> None:
    async with factory() as session:
        session.add(
            ReleasedNickname(nickname=nickname, released_by=released_by, released_at=released_at)
        )
        await session.commit()


async def _nickname_of(factory: async_sessionmaker[AsyncSession], user_id: uuid.UUID) -> str | None:
    async with factory() as session:
        return await session.scalar(select(User.nickname).where(User.id == user_id))


async def _released(
    factory: async_sessionmaker[AsyncSession],
) -> dict[str, tuple[uuid.UUID | None, datetime]]:
    async with factory() as session:
        rows = await session.execute(select(ReleasedNickname))
        return {row.nickname: (row.released_by, row.released_at) for row in rows.scalars()}


async def _free_for_others(factory: async_sessionmaker[AsyncSession], nickname: str) -> bool:
    async with factory() as session:
        taken = await session.scalar(
            text("SELECT pg_try_advisory_xact_lock(:space, hashtext(:nickname))"),
            {"space": NICKNAME_LOCK_SPACE, "nickname": nickname},
        )
        await session.rollback()
        return bool(taken)


async def _row_locked(factory: async_sessionmaker[AsyncSession], user_id: uuid.UUID) -> bool:
    async with factory() as session:
        try:
            await session.execute(
                text("SELECT id FROM users WHERE id = :id FOR UPDATE NOWAIT"), {"id": user_id}
            )
        except DBAPIError:
            return True
        finally:
            await session.rollback()
        return False


async def _ordered_by_lock_key(
    factory: async_sessionmaker[AsyncSession], first: str, second: str
) -> tuple[str, str]:
    async with factory() as session:
        keys = (
            await session.execute(
                text("SELECT hashtext(:first), hashtext(:second)"),
                {"first": first, "second": second},
            )
        ).one()
    return (first, second) if keys[0] < keys[1] else (second, first)


async def _waiting_for_advisory_lock(factory: async_sessionmaker[AsyncSession]) -> None:
    async with factory() as session:
        while True:
            waiting = await session.scalar(
                text("SELECT count(*) FROM pg_locks WHERE locktype = 'advisory' AND NOT granted")
            )
            await session.rollback()
            if waiting:
                return
            await asyncio.sleep(0.02)


def _record_statements(session: AsyncSession) -> list[str]:
    statements: list[str] = []

    def record(*args: Any) -> None:
        statements.append(args[2])

    event.listen(session.bind.sync_engine, "before_cursor_execute", record)
    return statements


async def test_lock_holds_every_given_nickname(
    factory: async_sessionmaker[AsyncSession],
) -> None:
    async with factory() as session:
        await SqlNicknameRepository(session).lock(["anna", "boris"])

        assert await _free_for_others(factory, "anna") is False
        assert await _free_for_others(factory, "boris") is False
        assert await _free_for_others(factory, "clara") is True


async def test_lock_is_released_on_rollback(factory: async_sessionmaker[AsyncSession]) -> None:
    async with factory() as session:
        await SqlNicknameRepository(session).lock(["anna"])
        await session.rollback()

    assert await _free_for_others(factory, "anna") is True


async def test_lock_is_released_on_commit(factory: async_sessionmaker[AsyncSession]) -> None:
    async with factory() as session:
        await SqlNicknameRepository(session).lock(["anna"])
        await session.commit()

        assert await _free_for_others(factory, "anna") is True


async def test_lock_waits_for_the_holder(factory: async_sessionmaker[AsyncSession]) -> None:
    async with factory() as holder, factory() as waiter:
        await SqlNicknameRepository(holder).lock(["anna"])
        waiting = asyncio.create_task(SqlNicknameRepository(waiter).lock(["anna"]))
        await asyncio.wait_for(_waiting_for_advisory_lock(factory), timeout=5)

        assert waiting.done() is False

        await holder.rollback()
        await asyncio.wait_for(waiting, timeout=5)
        await waiter.rollback()


async def test_lock_takes_keys_in_ascending_order(
    factory: async_sessionmaker[AsyncSession],
) -> None:
    lower, higher = await _ordered_by_lock_key(factory, "anna", "boris")
    async with factory() as holder, factory() as waiter:
        await SqlNicknameRepository(holder).lock([higher])
        waiting = asyncio.create_task(SqlNicknameRepository(waiter).lock([higher, lower]))
        await asyncio.wait_for(_waiting_for_advisory_lock(factory), timeout=5)

        assert await _free_for_others(factory, lower) is False

        await holder.rollback()
        await asyncio.wait_for(waiting, timeout=5)
        await waiter.rollback()


async def test_opposite_lock_orders_do_not_deadlock(
    factory: async_sessionmaker[AsyncSession],
) -> None:
    async def lock_in(order: list[str]) -> None:
        async with factory() as session:
            await SqlNicknameRepository(session).lock(order)
            await asyncio.sleep(0.05)
            await session.rollback()

    for _ in range(5):
        await asyncio.wait_for(
            asyncio.gather(lock_in(["anna", "boris"]), lock_in(["boris", "anna"])), timeout=5
        )


async def test_lock_tolerates_repeated_nickname(
    factory: async_sessionmaker[AsyncSession],
) -> None:
    async with factory() as session:
        await SqlNicknameRepository(session).lock(["anna", "anna"])

        assert await _free_for_others(factory, "anna") is False


async def test_lock_of_nothing_sends_no_queries(
    factory: async_sessionmaker[AsyncSession],
) -> None:
    async with factory() as session:
        statements = _record_statements(session)

        await SqlNicknameRepository(session).lock([])

        assert statements == []


async def test_owner_is_found_by_nickname(factory: async_sessionmaker[AsyncSession]) -> None:
    await _create_user(factory, "boris")
    owner = await _create_user(factory, "anna")

    async with factory() as session:
        assert await SqlNicknameRepository(session).get_owner("anna") == owner


@pytest.mark.parametrize("nickname", ["ann", "ANNA", "anna.", "clara"])
async def test_free_nickname_has_no_owner(
    factory: async_sessionmaker[AsyncSession], nickname: str
) -> None:
    await _create_user(factory, "anna")

    async with factory() as session:
        assert await SqlNicknameRepository(session).get_owner(nickname) is None


async def test_released_nickname_has_no_owner(factory: async_sessionmaker[AsyncSession]) -> None:
    former = await _create_user(factory, "boris")
    await _release(factory, "anna", former)

    async with factory() as session:
        assert await SqlNicknameRepository(session).get_owner("anna") is None


async def test_release_is_returned_as_dto(factory: async_sessionmaker[AsyncSession]) -> None:
    former = await _create_user(factory)
    await _release(factory, "anna", former, LONG_AGO)

    async with factory() as session:
        found = await SqlNicknameRepository(session).get_release("anna")

    assert found == ReleasedNicknameDTO(released_by=former, released_at=LONG_AGO)
    assert type(found) is ReleasedNicknameDTO


async def test_nickname_never_released_has_no_release(
    factory: async_sessionmaker[AsyncSession],
) -> None:
    await _release(factory, "boris", await _create_user(factory))

    async with factory() as session:
        assert await SqlNicknameRepository(session).get_release("anna") is None


async def test_release_outlives_its_deleted_owner(
    factory: async_sessionmaker[AsyncSession],
) -> None:
    former = await _create_user(factory)
    await _release(factory, "anna", former)
    async with factory() as session:
        await session.execute(text("DELETE FROM users WHERE id = :id"), {"id": former})
        await session.commit()

    async with factory() as session:
        found = await SqlNicknameRepository(session).get_release("anna")

    assert found == ReleasedNicknameDTO(released_by=None, released_at=LONG_AGO)


async def test_first_nickname_is_set_without_quarantine(
    factory: async_sessionmaker[AsyncSession],
) -> None:
    user_id = await _create_user(factory)

    async with factory() as session:
        await SqlNicknameRepository(session).change(user_id, None, "anna")
        await session.commit()

    assert await _nickname_of(factory, user_id) == "anna"
    assert await _released(factory) == {}


async def test_changed_nickname_goes_to_quarantine_at_transaction_time(
    factory: async_sessionmaker[AsyncSession],
) -> None:
    user_id = await _create_user(factory, "anna")

    async with factory() as session:
        await SqlNicknameRepository(session).change(user_id, "anna", "boris")
        transaction_time = await session.scalar(text("SELECT now()"))
        await session.commit()

    assert await _nickname_of(factory, user_id) == "boris"
    assert await _released(factory) == {"anna": (user_id, transaction_time)}


async def test_taken_nickname_leaves_quarantine(
    factory: async_sessionmaker[AsyncSession],
) -> None:
    user_id = await _create_user(factory, "boris")
    await _release(factory, "anna", user_id)

    async with factory() as session:
        await SqlNicknameRepository(session).change(user_id, "boris", "anna")
        await session.commit()

    assert await _nickname_of(factory, user_id) == "anna"
    assert set(await _released(factory)) == {"boris"}


async def test_released_again_nickname_restarts_quarantine(
    factory: async_sessionmaker[AsyncSession],
) -> None:
    user_id = await _create_user(factory, "anna")
    await _release(factory, "anna", None, LONG_AGO)

    async with factory() as session:
        await SqlNicknameRepository(session).change(user_id, "anna", "boris")
        transaction_time = await session.scalar(text("SELECT now()"))
        await session.commit()

    assert await _released(factory) == {"anna": (user_id, transaction_time)}


async def test_change_touches_only_the_given_user(
    factory: async_sessionmaker[AsyncSession],
) -> None:
    neighbour = await _create_user(factory, "clara")
    user_id = await _create_user(factory, "anna")

    async with factory() as session:
        await SqlNicknameRepository(session).change(user_id, "anna", "boris")
        await session.commit()

    assert await _nickname_of(factory, neighbour) == "clara"


async def test_change_never_commits(factory: async_sessionmaker[AsyncSession]) -> None:
    user_id = await _create_user(factory, "anna")

    async with factory() as session:
        await SqlNicknameRepository(session).change(user_id, "anna", "boris")
        await session.rollback()

    assert await _nickname_of(factory, user_id) == "anna"
    assert await _released(factory) == {}


async def test_get_for_update_returns_user_dto(
    factory: async_sessionmaker[AsyncSession],
) -> None:
    user_id = await _create_user(factory, "anna")

    async with factory() as session:
        found = await SqlUserRepository(session).get_for_update(user_id)

    assert type(found) is UserDTO
    assert found.id == user_id
    assert found.nickname == "anna"


async def test_get_for_update_of_unknown_user_returns_none(
    factory: async_sessionmaker[AsyncSession],
) -> None:
    await _create_user(factory)

    async with factory() as session:
        assert await SqlUserRepository(session).get_for_update(uuid.uuid7()) is None


async def test_get_for_update_locks_the_row_until_transaction_ends(
    factory: async_sessionmaker[AsyncSession],
) -> None:
    user_id = await _create_user(factory)

    async with factory() as session:
        await SqlUserRepository(session).get_for_update(user_id)

        assert await _row_locked(factory, user_id) is True

        await session.rollback()

        assert await _row_locked(factory, user_id) is False


async def test_plain_get_does_not_lock_the_row(factory: async_sessionmaker[AsyncSession]) -> None:
    user_id = await _create_user(factory)

    async with factory() as session:
        await SqlUserRepository(session).get(user_id)

        assert await _row_locked(factory, user_id) is False


async def test_get_reads_the_nickname(factory: async_sessionmaker[AsyncSession]) -> None:
    user_id = await _create_user(factory, "anna")

    async with factory() as session:
        found = await SqlUserRepository(session).get(user_id)

    assert found is not None
    assert found.nickname == "anna"
