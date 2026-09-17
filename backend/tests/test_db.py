import os
import re
import uuid
from collections.abc import AsyncIterator, Iterator
from datetime import UTC, datetime

import pytest
from sqlalchemy import inspect, select, text
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.pool import QueuePool
from testcontainers.community.postgres import PostgresContainer

from app.core.config import get_settings
from app.core.db import dispose_engine, get_engine, get_session, get_session_factory
from app.core.models import Base, IdMixin, TimestampMixin

DURATION = re.compile(r"^(\d+)(ms|s|min)$")
UNITS = {"ms": 1, "s": 1000, "min": 60_000}


class Widget(IdMixin, TimestampMixin, Base):
    __tablename__ = "t_widgets"

    title: Mapped[str] = mapped_column(unique=True)


def _pool() -> QueuePool:
    pool = get_engine().pool
    assert isinstance(pool, QueuePool)
    return pool


async def _exhaust(generator: AsyncIterator[AsyncSession]) -> None:
    with pytest.raises(StopAsyncIteration):
        await anext(generator)


def _to_ms(value: str) -> int:
    match = DURATION.match(value)
    assert match is not None, value
    return int(match.group(1)) * UNITS[match.group(2)]


@pytest.fixture(scope="session")
def postgres() -> Iterator[PostgresContainer]:
    with PostgresContainer("postgres:17-alpine") as container:
        yield container


@pytest.fixture(scope="session", autouse=True)
def _point_at_container(postgres: PostgresContainer) -> Iterator[None]:
    overrides = {
        "DB__HOST": postgres.get_container_host_ip(),
        "DB__PORT": str(postgres.get_exposed_port(5432)),
        "DB__USER": postgres.username,
        "DB__PASSWORD": postgres.password,
        "DB__NAME": postgres.dbname,
    }
    saved = {key: os.environ.get(key) for key in overrides}
    os.environ.update(overrides)
    get_settings.cache_clear()

    yield

    for key, value in saved.items():
        if value is None:
            os.environ.pop(key, None)
        else:
            os.environ[key] = value
    get_settings.cache_clear()


@pytest.fixture(autouse=True)
async def _fresh_engine() -> AsyncIterator[None]:
    get_engine.cache_clear()
    get_session_factory.cache_clear()

    yield

    await dispose_engine()


@pytest.fixture
async def tables() -> AsyncIterator[None]:
    async with get_engine().begin() as connection:
        await connection.run_sync(
            Base.metadata.create_all, tables=[Base.metadata.tables["t_widgets"]]
        )

    yield

    async with get_engine().begin() as connection:
        await connection.run_sync(
            Base.metadata.drop_all, tables=[Base.metadata.tables["t_widgets"]]
        )


@pytest.fixture
async def session(tables: None) -> AsyncIterator[AsyncSession]:
    factory = get_session_factory()
    async with factory() as instance:
        yield instance


async def test_engine_is_reused() -> None:
    assert get_engine() is get_engine()


async def test_dispose_replaces_engine() -> None:
    before = get_engine()

    await dispose_engine()

    assert get_engine() is not before


async def test_dispose_rebinds_session_factory() -> None:
    get_session_factory()

    await dispose_engine()

    assert get_session_factory().kw["bind"] is get_engine()


async def test_statement_timeout_reaches_server() -> None:
    settings = get_settings()

    async with get_engine().connect() as connection:
        value = (await connection.execute(text("SHOW statement_timeout"))).scalar_one()

    assert _to_ms(value) == settings.db.statement_timeout_ms


async def test_idle_in_transaction_timeout_reaches_server() -> None:
    settings = get_settings()

    async with get_engine().connect() as connection:
        value = (
            await connection.execute(text("SHOW idle_in_transaction_session_timeout"))
        ).scalar_one()

    assert _to_ms(value) == settings.db.idle_in_transaction_timeout_ms


async def test_pool_is_configured_from_settings() -> None:
    settings = get_settings()
    pool = _pool()

    assert pool.size() == settings.db.pool_size
    assert pool._max_overflow == settings.db.max_overflow


async def test_dependency_yields_distinct_sessions(tables: None) -> None:
    first_gen = get_session()
    second_gen = get_session()

    first = await first_gen.__anext__()
    second = await second_gen.__anext__()

    assert first is not second

    await _exhaust(first_gen)
    await _exhaust(second_gen)


async def test_dependency_returns_connection_to_pool(tables: None) -> None:
    generator = get_session()
    instance = await generator.__anext__()
    await instance.execute(select(Widget))
    assert _pool().checkedout() == 1

    await _exhaust(generator)

    assert _pool().checkedout() == 0
    assert not instance.in_transaction()


async def test_uncommitted_changes_are_invisible_elsewhere(session: AsyncSession) -> None:
    session.add(Widget(title="черновик"))
    await session.flush()

    factory = get_session_factory()
    async with factory() as other:
        found = (await other.execute(select(Widget).where(Widget.title == "черновик"))).all()

    assert found == []


async def test_committed_changes_are_visible_elsewhere(session: AsyncSession) -> None:
    session.add(Widget(title="сохранённый"))
    await session.commit()

    factory = get_session_factory()
    async with factory() as other:
        found = (await other.execute(select(Widget).where(Widget.title == "сохранённый"))).all()

    assert len(found) == 1


async def test_dependency_does_not_commit_by_itself(tables: None) -> None:
    generator = get_session()
    instance = await generator.__anext__()
    instance.add(Widget(title="без коммита"))
    await instance.flush()
    await _exhaust(generator)

    factory = get_session_factory()
    async with factory() as other:
        found = (await other.execute(select(Widget))).all()

    assert found == []


async def test_attributes_are_readable_after_commit(session: AsyncSession) -> None:
    widget = Widget(title="после коммита")
    session.add(widget)

    await session.commit()

    assert widget.title == "после коммита"
    assert widget.id is not None


async def test_constraint_names_follow_convention(tables: None) -> None:
    async with get_engine().connect() as connection:
        primary = await connection.run_sync(
            lambda sync: inspect(sync).get_pk_constraint("t_widgets")
        )
        unique = await connection.run_sync(
            lambda sync: inspect(sync).get_unique_constraints("t_widgets")
        )

    assert primary["name"] == "t_widgets_pkey"
    assert [item["name"] for item in unique] == ["t_widgets_title_key"]


async def test_identifiers_are_generated_and_unique(session: AsyncSession) -> None:
    first = Widget(title="первый")
    second = Widget(title="второй")
    session.add_all([first, second])

    await session.commit()

    assert isinstance(first.id, uuid.UUID)
    assert first.id != second.id


async def test_identifiers_are_time_ordered(session: AsyncSession) -> None:
    first = Widget(title="раньше")
    session.add(first)
    await session.commit()

    second = Widget(title="позже")
    session.add(second)
    await session.commit()

    assert first.id < second.id


async def test_timestamps_are_timezone_aware(session: AsyncSession) -> None:
    widget = Widget(title="со временем")
    session.add(widget)

    await session.commit()
    await session.refresh(widget)

    assert widget.created_at.tzinfo is not None
    assert widget.updated_at.tzinfo is not None


async def test_created_at_is_filled_by_server(session: AsyncSession) -> None:
    before = datetime.now(UTC)
    widget = Widget(title="серверное время")
    session.add(widget)

    await session.commit()
    await session.refresh(widget)

    assert before <= widget.created_at <= datetime.now(UTC)


async def test_updated_at_moves_on_update(session: AsyncSession) -> None:
    widget = Widget(title="до правки")
    session.add(widget)
    await session.commit()
    await session.refresh(widget)
    original = widget.updated_at

    widget.title = "после правки"
    await session.commit()
    await session.refresh(widget)

    assert widget.updated_at > original
