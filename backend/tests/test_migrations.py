import asyncio
import uuid
from collections.abc import AsyncIterator, Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from alembic.autogenerate import compare_metadata
from alembic.config import Config
from alembic.runtime.migration import MigrationContext
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncConnection

from alembic import command
from app.core.db import dispose_engine, get_engine, get_session_factory
from app.core.models import Base

ALEMBIC_INI = Path(__file__).resolve().parents[1] / "alembic.ini"
EXPECTED_TABLES = {"users", "workspaces", "memberships", "invites"}


def _config() -> Config:
    return Config(str(ALEMBIC_INI))


@pytest.fixture(scope="module")
def migrated(_point_at_container: None) -> Iterator[None]:
    command.upgrade(_config(), "head")

    yield

    command.downgrade(_config(), "base")


@pytest.fixture(autouse=True)
async def _fresh_engine(migrated: None) -> AsyncIterator[None]:
    get_engine.cache_clear()
    get_session_factory.cache_clear()

    yield

    await dispose_engine()


async def _tables(connection: AsyncConnection) -> set[str]:
    rows = await connection.execute(
        text("SELECT tablename FROM pg_tables WHERE schemaname = 'public'")
    )
    return {row[0] for row in rows}


async def _type_exists(connection: AsyncConnection, name: str) -> bool:
    found = await connection.execute(
        text("SELECT 1 FROM pg_type WHERE typname = :name"), {"name": name}
    )
    return found.first() is not None


async def _new_user(connection: AsyncConnection, email: str) -> uuid.UUID:
    identifier = uuid.uuid7()
    await connection.execute(
        text(
            "INSERT INTO users (id, email, google_sub, display_name)"
            " VALUES (:id, :email, :sub, :name)"
        ),
        {"id": identifier, "email": email, "sub": f"sub-{identifier}", "name": "кто-то"},
    )
    return identifier


async def _new_workspace(connection: AsyncConnection, owner_id: uuid.UUID) -> uuid.UUID:
    identifier = uuid.uuid7()
    await connection.execute(
        text("INSERT INTO workspaces (id, name, owner_id) VALUES (:id, :name, :owner)"),
        {"id": identifier, "name": "кухня", "owner": owner_id},
    )
    return identifier


async def _join(
    connection: AsyncConnection, user_id: uuid.UUID, workspace_id: uuid.UUID, role: str = "member"
) -> None:
    await connection.execute(
        text(
            "INSERT INTO memberships (user_id, workspace_id, role)"
            " VALUES (:user, :workspace, :role)"
        ),
        {"user": user_id, "workspace": workspace_id, "role": role},
    )


async def test_migration_creates_expected_tables() -> None:
    async with get_engine().connect() as connection:
        assert await _tables(connection) >= EXPECTED_TABLES


async def test_enum_stores_values_not_member_names() -> None:
    async with get_engine().connect() as connection:
        rows = await connection.execute(text("SELECT unnest(enum_range(NULL::workspace_role))"))

    assert [row[0] for row in rows] == ["owner", "member"]


async def test_membership_primary_key_is_user_id_only() -> None:
    async with get_engine().connect() as connection:
        rows = await connection.execute(
            text("""
                SELECT a.attname FROM pg_index i
                JOIN pg_attribute a ON a.attrelid = i.indrelid AND a.attnum = ANY(i.indkey)
                WHERE i.indrelid = 'memberships'::regclass AND i.indisprimary
            """)
        )

    assert [row[0] for row in rows] == ["user_id"]


async def test_constraint_names_follow_convention() -> None:
    async with get_engine().connect() as connection:
        rows = await connection.execute(
            text("""
                SELECT conname FROM pg_constraint
                WHERE conrelid = 'invites'::regclass AND contype IN ('p', 'f', 'u')
            """)
        )

    assert {row[0] for row in rows} == {
        "invites_pkey",
        "invites_token_hash_key",
        "invites_workspace_id_fkey",
        "invites_created_by_fkey",
        "invites_used_by_fkey",
    }


async def test_email_is_unique_ignoring_case() -> None:
    async with get_engine().begin() as connection:
        await _new_user(connection, "Nika@Example.COM")

        with pytest.raises(IntegrityError):
            await _new_user(connection, "nika@example.com")


async def test_emails_differing_beyond_case_coexist() -> None:
    async with get_engine().begin() as connection:
        await _new_user(connection, "one@example.com")
        await _new_user(connection, "two@example.com")

        count = await connection.execute(
            text("SELECT count(*) FROM users WHERE email LIKE '%@example.com'")
        )
        assert count.scalar_one() == 2
        await connection.rollback()


async def test_user_cannot_belong_to_two_workspaces() -> None:
    async with get_engine().begin() as connection:
        user_id = await _new_user(connection, "double@example.com")
        first = await _new_workspace(connection, user_id)
        second = await _new_workspace(connection, user_id)
        await _join(connection, user_id, first)

        with pytest.raises(IntegrityError):
            await _join(connection, user_id, second)


async def test_deleting_user_removes_membership() -> None:
    factory = get_session_factory()
    async with factory() as session:
        connection = await session.connection()
        owner_id = await _new_user(connection, "owner@example.com")
        workspace_id = await _new_workspace(connection, owner_id)
        member_id = await _new_user(connection, "member@example.com")
        await _join(connection, member_id, workspace_id)

        await connection.execute(text("DELETE FROM users WHERE id = :id"), {"id": member_id})

        left = await connection.execute(
            text("SELECT count(*) FROM memberships WHERE user_id = :id"), {"id": member_id}
        )
        assert left.scalar_one() == 0
        await session.rollback()


async def test_workspace_owner_cannot_be_deleted() -> None:
    async with get_engine().begin() as connection:
        owner_id = await _new_user(connection, "protected@example.com")
        await _new_workspace(connection, owner_id)

        with pytest.raises(IntegrityError):
            await connection.execute(text("DELETE FROM users WHERE id = :id"), {"id": owner_id})


async def test_deleting_invite_author_keeps_the_invite() -> None:
    factory = get_session_factory()
    async with factory() as session:
        connection = await session.connection()
        owner_id = await _new_user(connection, "inviteowner@example.com")
        workspace_id = await _new_workspace(connection, owner_id)
        author_id = await _new_user(connection, "author@example.com")
        invite_id = uuid.uuid7()
        await connection.execute(
            text(
                "INSERT INTO invites (id, workspace_id, token_hash, created_by, expires_at)"
                " VALUES (:id, :workspace, :hash, :author, :expires)"
            ),
            {
                "id": invite_id,
                "workspace": workspace_id,
                "hash": b"\x01" * 32,
                "author": author_id,
                "expires": datetime.now(UTC) + timedelta(days=7),
            },
        )

        await connection.execute(text("DELETE FROM users WHERE id = :id"), {"id": author_id})

        row = await connection.execute(
            text("SELECT created_by FROM invites WHERE id = :id"), {"id": invite_id}
        )
        assert row.scalar_one() is None
        await session.rollback()


async def test_models_and_schema_do_not_drift() -> None:
    def _diff(sync_connection: Any) -> list[Any]:
        context = MigrationContext.configure(sync_connection)
        return list(compare_metadata(context, Base.metadata))

    async with get_engine().connect() as connection:
        differences = await connection.run_sync(_diff)

    assert differences == []


async def test_downgrade_removes_tables_and_enum_type() -> None:
    await dispose_engine()
    await asyncio.to_thread(command.downgrade, _config(), "base")

    get_engine.cache_clear()
    get_session_factory.cache_clear()
    async with get_engine().connect() as connection:
        assert not (EXPECTED_TABLES & await _tables(connection))
        assert not await _type_exists(connection, "workspace_role")

    await dispose_engine()
    await asyncio.to_thread(command.upgrade, _config(), "head")

    get_engine.cache_clear()
    get_session_factory.cache_clear()
    async with get_engine().connect() as connection:
        assert await _tables(connection) >= EXPECTED_TABLES
        assert await _type_exists(connection, "workspace_role")
