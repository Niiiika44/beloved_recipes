import re
import uuid
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import MetaData, inspect, select, text
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy.pool import QueuePool

from app.core.config import get_settings
from app.core.db import dispose_engine, get_engine, get_session_factory
from app.core.models import NAMING_CONVENTION, IdMixin, TimestampMixin

DURATION = re.compile(r"^(\d+)(ms|s|min)$")
UNITS = {"ms": 1, "s": 1000, "min": 60_000}
CLOCK_SKEW_TOLERANCE = timedelta(seconds=5)


class SandboxBase(DeclarativeBase):
    metadata = MetaData(naming_convention=NAMING_CONVENTION)


class Widget(IdMixin, TimestampMixin, SandboxBase):
    __tablename__ = "t_widgets"

    title: Mapped[str] = mapped_column(unique=True)


def _pool() -> QueuePool:
    pool = get_engine().pool
    assert isinstance(pool, QueuePool)
    return pool


def _to_ms(value: str) -> int:
    match = DURATION.match(value)
    assert match is not None, value
    return int(match.group(1)) * UNITS[match.group(2)]


@pytest.fixture(autouse=True)
async def _fresh_engine(_point_at_container: None) -> AsyncIterator[None]:
    get_engine.cache_clear()
    get_session_factory.cache_clear()

    yield

    await dispose_engine()


@pytest.fixture
async def tables() -> AsyncIterator[None]:
    async with get_engine().begin() as connection:
        await connection.run_sync(
            SandboxBase.metadata.create_all, tables=[SandboxBase.metadata.tables["t_widgets"]]
        )

    yield

    async with get_engine().begin() as connection:
        await connection.run_sync(
            SandboxBase.metadata.drop_all, tables=[SandboxBase.metadata.tables["t_widgets"]]
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
    widget = Widget(title="серверное время")
    session.add(widget)

    await session.commit()
    await session.refresh(widget)

    assert abs(widget.created_at - datetime.now(UTC)) < CLOCK_SKEW_TOLERANCE


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
