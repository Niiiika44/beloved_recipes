import asyncio
import re
import shutil
import uuid
from collections.abc import AsyncIterator, Callable, Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from alembic.autogenerate import compare_metadata
from alembic.config import Config
from alembic.runtime.migration import MigrationContext
from alembic.script import ScriptDirectory
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncConnection

from alembic import command
from app.core.db import dispose_engine, get_engine, get_session_factory
from app.core.models import Base

ALEMBIC_INI = Path(__file__).resolve().parents[1] / "alembic.ini"
ALEMBIC_DIR = ALEMBIC_INI.parent / "alembic"
EXPECTED_TABLES = {
    "users",
    "workspaces",
    "memberships",
    "invites",
    "user_identities",
    "released_nicknames",
}
REVISION_BEFORE_IDENTITIES = "0001"
REVISION_BEFORE_NICKNAMES = "0002"


def _config() -> Config:
    return Config(str(ALEMBIC_INI))


async def _migrate(step: Callable[[Config, str], None], revision: str) -> None:
    await dispose_engine()
    await asyncio.to_thread(step, _config(), revision)
    get_engine.cache_clear()
    get_session_factory.cache_clear()


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


@pytest.fixture
async def _restores_head(_fresh_engine: None) -> AsyncIterator[None]:
    yield

    async with get_engine().begin() as connection:
        await connection.execute(text("TRUNCATE users CASCADE"))
    await _migrate(command.upgrade, "head")


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
        text("INSERT INTO users (id, email, display_name) VALUES (:id, :email, :name)"),
        {"id": identifier, "email": email, "name": "кто-то"},
    )
    return identifier


async def _new_identity(connection: AsyncConnection, user_id: uuid.UUID, subject: str) -> None:
    await connection.execute(
        text(
            "INSERT INTO user_identities (id, user_id, provider, subject)"
            " VALUES (:id, :user, 'google', :subject)"
        ),
        {"id": uuid.uuid7(), "user": user_id, "subject": subject},
    )


async def _new_user_before_identities(connection: AsyncConnection, email: str, sub: str) -> None:
    await connection.execute(
        text(
            "INSERT INTO users (id, email, google_sub, display_name)"
            " VALUES (:id, :email, :sub, :name)"
        ),
        {"id": uuid.uuid7(), "email": email, "sub": sub, "name": "кто-то"},
    )


async def _set_nickname(connection: AsyncConnection, user_id: uuid.UUID, nickname: str) -> None:
    await connection.execute(
        text("UPDATE users SET nickname = :nickname WHERE id = :id"),
        {"nickname": nickname, "id": user_id},
    )


async def _quarantine(connection: AsyncConnection, nickname: str, user_id: uuid.UUID) -> None:
    await connection.execute(
        text("INSERT INTO released_nicknames (nickname, released_by) VALUES (:nickname, :user)"),
        {"nickname": nickname, "user": user_id},
    )


async def _users_columns(connection: AsyncConnection) -> set[str]:
    rows = await connection.execute(
        text("SELECT column_name FROM information_schema.columns WHERE table_name = 'users'")
    )
    return {row[0] for row in rows}


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
        assert not await _type_exists(connection, "identity_provider")

    await dispose_engine()
    await asyncio.to_thread(command.upgrade, _config(), "head")

    get_engine.cache_clear()
    get_session_factory.cache_clear()
    async with get_engine().connect() as connection:
        assert await _tables(connection) >= EXPECTED_TABLES
        assert await _type_exists(connection, "workspace_role")
        assert await _type_exists(connection, "identity_provider")


async def test_identity_provider_stores_values_not_member_names() -> None:
    async with get_engine().connect() as connection:
        rows = await connection.execute(text("SELECT unnest(enum_range(NULL::identity_provider))"))

    assert [row[0] for row in rows] == ["google"]


async def test_user_identity_constraint_names_are_explicit() -> None:
    async with get_engine().connect() as connection:
        rows = await connection.execute(
            text("""
                SELECT conname FROM pg_constraint
                WHERE conrelid = 'user_identities'::regclass AND contype IN ('p', 'f', 'u')
            """)
        )

    assert {row[0] for row in rows} == {
        "user_identities_pkey",
        "user_identities_user_id_fkey",
        "user_identities_provider_subject_key",
        "user_identities_user_id_provider_key",
    }


async def test_google_account_belongs_to_one_user() -> None:
    async with get_engine().begin() as connection:
        first = await _new_user(connection, "first@example.com")
        second = await _new_user(connection, "second@example.com")
        await _new_identity(connection, first, "shared-sub")

        with pytest.raises(IntegrityError):
            await _new_identity(connection, second, "shared-sub")


async def test_user_cannot_have_two_identities_of_one_provider() -> None:
    async with get_engine().begin() as connection:
        user_id = await _new_user(connection, "twice@example.com")
        await _new_identity(connection, user_id, "old-sub")

        with pytest.raises(IntegrityError):
            await _new_identity(connection, user_id, "new-sub")


async def test_deleting_user_removes_identities() -> None:
    factory = get_session_factory()
    async with factory() as session:
        connection = await session.connection()
        user_id = await _new_user(connection, "leaving@example.com")
        await _new_identity(connection, user_id, "leaving-sub")

        await connection.execute(text("DELETE FROM users WHERE id = :id"), {"id": user_id})

        left = await connection.execute(
            text("SELECT count(*) FROM user_identities WHERE user_id = :id"), {"id": user_id}
        )
        assert left.scalar_one() == 0
        await session.rollback()


async def test_new_user_starts_with_unverified_email() -> None:
    factory = get_session_factory()
    async with factory() as session:
        connection = await session.connection()
        user_id = await _new_user(connection, "fresh@example.com")

        verified_at = await connection.execute(
            text("SELECT email_verified_at FROM users WHERE id = :id"), {"id": user_id}
        )
        assert verified_at.scalar_one() is None
        await session.rollback()


@pytest.mark.usefixtures("_restores_head")
async def test_upgrade_moves_google_sub_into_identities() -> None:
    await _migrate(command.downgrade, REVISION_BEFORE_IDENTITIES)
    async with get_engine().begin() as connection:
        await _new_user_before_identities(connection, "a@example.com", "sub-a")
        await _new_user_before_identities(connection, "b@example.com", "sub-b")

    await _migrate(command.upgrade, "head")

    async with get_engine().connect() as connection:
        rows = await connection.execute(
            text("""
                SELECT u.email, i.id, i.provider::text, i.subject,
                       u.email_verified_at = u.created_at AS verified_at_creation
                FROM users u JOIN user_identities i ON i.user_id = u.id
                ORDER BY u.email
            """)
        )
        moved = rows.all()
        columns = await _users_columns(connection)

    assert [(row.email, row.provider, row.subject) for row in moved] == [
        ("a@example.com", "google", "sub-a"),
        ("b@example.com", "google", "sub-b"),
    ]
    assert all(row.id.version == 7 for row in moved)
    assert all(row.verified_at_creation for row in moved)
    assert "google_sub" not in columns


@pytest.mark.usefixtures("_restores_head")
async def test_downgrade_restores_google_sub() -> None:
    async with get_engine().begin() as connection:
        first = await _new_user(connection, "a@example.com")
        second = await _new_user(connection, "b@example.com")
        await _new_identity(connection, first, "sub-a")
        await _new_identity(connection, second, "sub-b")

    await _migrate(command.downgrade, REVISION_BEFORE_IDENTITIES)

    async with get_engine().connect() as connection:
        rows = await connection.execute(text("SELECT email, google_sub FROM users ORDER BY email"))
        restored = [tuple(row) for row in rows]
        nullable = await connection.execute(
            text("""
                SELECT is_nullable FROM information_schema.columns
                WHERE table_name = 'users' AND column_name = 'google_sub'
            """)
        )
        constraint = await connection.execute(
            text("SELECT 1 FROM pg_constraint WHERE conname = 'users_google_sub_key'")
        )
        nullable_value = nullable.scalar_one()
        constraint_found = constraint.first() is not None
        columns = await _users_columns(connection)
        tables = await _tables(connection)
        type_left = await _type_exists(connection, "identity_provider")

    assert restored == [("a@example.com", "sub-a"), ("b@example.com", "sub-b")]
    assert nullable_value == "NO"
    assert constraint_found
    assert "email_verified_at" not in columns
    assert "user_identities" not in tables
    assert not type_left


@pytest.mark.usefixtures("_restores_head")
async def test_downgrade_refuses_user_without_google_identity() -> None:
    async with get_engine().begin() as connection:
        with_google = await _new_user(connection, "google@example.com")
        await _new_identity(connection, with_google, "sub-google")
        await _new_user(connection, "password@example.com")

    with pytest.raises(RuntimeError, match="1 users have no Google identity"):
        await _migrate(command.downgrade, REVISION_BEFORE_IDENTITIES)

    get_engine.cache_clear()
    get_session_factory.cache_clear()
    async with get_engine().connect() as connection:
        version = await connection.execute(text("SELECT version_num FROM alembic_version"))
        users = await connection.execute(text("SELECT count(*) FROM users"))
        identities = await connection.execute(text("SELECT count(*) FROM user_identities"))
        assert version.scalar_one() == ScriptDirectory.from_config(_config()).get_current_head()
        assert users.scalar_one() == 2
        assert identities.scalar_one() == 1


async def test_users_without_nickname_coexist() -> None:
    factory = get_session_factory()
    async with factory() as session:
        connection = await session.connection()
        await _new_user(connection, "first@example.com")
        await _new_user(connection, "second@example.com")

        count = await connection.execute(text("SELECT count(*) FROM users WHERE nickname IS NULL"))
        assert count.scalar_one() == 2
        await session.rollback()


async def test_nickname_is_unique() -> None:
    async with get_engine().begin() as connection:
        first = await _new_user(connection, "first@example.com")
        second = await _new_user(connection, "second@example.com")
        await _set_nickname(connection, first, "chef.anna")

        with pytest.raises(IntegrityError, match="users_nickname_key"):
            await _set_nickname(connection, second, "chef.anna")


async def test_user_nickname_must_be_lowercase() -> None:
    async with get_engine().begin() as connection:
        user_id = await _new_user(connection, "upper@example.com")

        with pytest.raises(IntegrityError, match="users_nickname_lowercase_check"):
            await _set_nickname(connection, user_id, "Chef.Anna")


async def test_quarantined_nickname_must_be_lowercase() -> None:
    async with get_engine().begin() as connection:
        user_id = await _new_user(connection, "upper@example.com")

        with pytest.raises(IntegrityError, match="released_nicknames_nickname_lowercase_check"):
            await _quarantine(connection, "Chef.Anna", user_id)


async def test_nickname_is_quarantined_once() -> None:
    async with get_engine().begin() as connection:
        first = await _new_user(connection, "first@example.com")
        second = await _new_user(connection, "second@example.com")
        await _quarantine(connection, "chef.anna", first)

        with pytest.raises(IntegrityError, match="released_nicknames_pkey"):
            await _quarantine(connection, "chef.anna", second)


async def test_quarantine_records_release_time() -> None:
    factory = get_session_factory()
    async with factory() as session:
        connection = await session.connection()
        user_id = await _new_user(connection, "released@example.com")
        await _quarantine(connection, "chef.anna", user_id)

        released = await connection.execute(
            text("SELECT released_at = now() FROM released_nicknames WHERE nickname = 'chef.anna'")
        )
        assert released.scalar_one() is True
        await session.rollback()


async def test_quarantine_outlives_deleted_user() -> None:
    factory = get_session_factory()
    async with factory() as session:
        connection = await session.connection()
        user_id = await _new_user(connection, "leaving@example.com")
        await _quarantine(connection, "chef.anna", user_id)

        await connection.execute(text("DELETE FROM users WHERE id = :id"), {"id": user_id})

        row = await connection.execute(
            text("SELECT released_by FROM released_nicknames WHERE nickname = 'chef.anna'")
        )
        assert row.scalar_one() is None
        await session.rollback()


async def test_released_nickname_constraint_names_follow_convention() -> None:
    async with get_engine().connect() as connection:
        constraints = await connection.execute(
            text("""
                SELECT conname FROM pg_constraint
                WHERE conrelid = 'released_nicknames'::regclass AND contype IN ('p', 'f', 'u', 'c')
            """)
        )
        indexes = await connection.execute(
            text("SELECT indexname FROM pg_indexes WHERE tablename = 'released_nicknames'")
        )
        constraint_names = {row[0] for row in constraints}
        index_names = {row[0] for row in indexes}

    assert constraint_names == {
        "released_nicknames_pkey",
        "released_nicknames_released_by_fkey",
        "released_nicknames_nickname_lowercase_check",
    }
    assert "released_nicknames_released_by_idx" in index_names


@pytest.mark.usefixtures("_restores_head")
async def test_downgrade_before_nicknames_removes_them() -> None:
    await _migrate(command.downgrade, REVISION_BEFORE_NICKNAMES)

    async with get_engine().connect() as connection:
        columns = await _users_columns(connection)
        tables = await _tables(connection)
        constraints = await connection.execute(
            text("SELECT conname FROM pg_constraint WHERE conname LIKE 'users_nickname%'")
        )
        leftover = [row[0] for row in constraints]

    assert "nickname" not in columns
    assert "released_nicknames" not in tables
    assert leftover == []


def test_revisions_are_numbered_in_sequence() -> None:
    script = ScriptDirectory.from_config(_config())

    revisions = sorted(revision.revision for revision in script.walk_revisions())

    assert all(re.fullmatch(r"\d{4}", revision) for revision in revisions)
    assert revisions == [f"{number:04d}" for number in range(1, len(revisions) + 1)]


def test_revision_files_start_with_their_number() -> None:
    script = ScriptDirectory.from_config(_config())

    for revision in script.walk_revisions():
        assert revision.path is not None
        assert Path(revision.path).name.startswith(f"{revision.revision}_")


@pytest.mark.parametrize("autogenerate", [False, True])
async def test_new_revision_gets_next_number(tmp_path: Path, autogenerate: bool) -> None:
    location = tmp_path / "alembic"
    shutil.copytree(ALEMBIC_DIR, location, ignore=shutil.ignore_patterns("__pycache__"))
    config = _config()
    config.set_main_option("script_location", str(location))
    head = ScriptDirectory.from_config(config).get_current_head()
    assert head is not None

    await dispose_engine()
    await asyncio.to_thread(command.revision, config, "probe", autogenerate=autogenerate)
    get_engine.cache_clear()
    get_session_factory.cache_clear()

    expected = f"{int(head) + 1:04d}"
    assert (location / "versions" / f"{expected}_probe.py").is_file()
    assert ScriptDirectory.from_config(config).get_current_head() == expected
