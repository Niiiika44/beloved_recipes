import uuid
from collections.abc import AsyncIterator
from datetime import timedelta
from typing import Any

import pytest
from sqlalchemy import func, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.db import dispose_engine, get_engine, get_session_factory
from app.modules.identity.domain.enums import IdentityProvider
from app.modules.identity.infrastructure.models import PasswordCredential, User, UserIdentity
from app.modules.identity.infrastructure.repositories import (
    SqlPasswordRepository,
    SqlUserRepository,
)

GOOGLE = IdentityProvider.GOOGLE


@pytest.fixture
async def session(migrated_schema: None) -> AsyncIterator[AsyncSession]:
    get_engine.cache_clear()
    get_session_factory.cache_clear()
    async with get_session_factory()() as instance:
        yield instance
        await instance.rollback()
    await dispose_engine()


async def _user(session: AsyncSession, **overrides: Any) -> User:
    suffix = uuid.uuid4().hex[:8]
    values: dict[str, Any] = {
        "email": f"cook-{suffix}@example.com",
        "display_name": f"Cook {suffix}",
        "avatar_url": f"https://example.com/{suffix}.png",
    }
    user = User(**(values | overrides))
    session.add(user)
    await session.flush()
    return user


def _subject() -> str:
    return uuid.uuid4().hex


async def _identities(session: AsyncSession) -> list[tuple[uuid.UUID, str, str]]:
    rows = await session.execute(
        select(UserIdentity.user_id, UserIdentity.provider, UserIdentity.subject)
    )
    return [(row.user_id, row.provider.value, row.subject) for row in rows]


async def test_create_from_google_is_verified_and_has_the_avatar(session: AsyncSession) -> None:
    users = SqlUserRepository(session)

    user_id = await users.create(
        "anna@example.org", "Anna", avatar_url="https://g/anna.png", email_verified=True
    )

    assert user_id is not None
    user = await users.get(user_id)
    assert user is not None
    assert user.email_verified_at is not None
    assert user.avatar_url == "https://g/anna.png"


async def test_create_by_default_is_unverified_without_avatar(session: AsyncSession) -> None:
    users = SqlUserRepository(session)

    user_id = await users.create("anna@example.org", "Anna")

    assert user_id is not None
    user = await users.get(user_id)
    assert user is not None
    assert user.email_verified_at is None
    assert user.avatar_url is None


async def test_linked_identity_finds_its_user(session: AsyncSession) -> None:
    anna = await _user(session)
    await _user(session)
    users = SqlUserRepository(session)
    subject = _subject()

    await users.link_identity(anna.id, GOOGLE, subject)

    found = await users.find_by_identity(GOOGLE, subject)
    assert found is not None
    assert found.id == anna.id
    assert found.email == anna.email
    assert await users.get_identity_subject(anna.id, GOOGLE) == subject


async def test_unknown_identity_finds_nobody(session: AsyncSession) -> None:
    anna = await _user(session)
    users = SqlUserRepository(session)
    await users.link_identity(anna.id, GOOGLE, _subject())

    assert await users.find_by_identity(GOOGLE, _subject()) is None
    assert await users.get_identity_subject((await _user(session)).id, GOOGLE) is None


async def test_relink_replaces_the_subject_of_the_same_user(session: AsyncSession) -> None:
    anna = await _user(session)
    users = SqlUserRepository(session)
    old, new = _subject(), _subject()
    await users.link_identity(anna.id, GOOGLE, old)

    await users.link_identity(anna.id, GOOGLE, new)

    assert await _identities(session) == [(anna.id, "google", new)]
    assert await users.find_by_identity(GOOGLE, old) is None
    assert await users.get_identity_subject(anna.id, GOOGLE) == new


async def test_relink_touches_the_update_time(session: AsyncSession) -> None:
    anna = await _user(session)
    users = SqlUserRepository(session)
    await users.link_identity(anna.id, GOOGLE, _subject())
    await session.execute(update(UserIdentity).values(updated_at=func.now() - timedelta(hours=1)))

    await users.link_identity(anna.id, GOOGLE, _subject())

    touched = await session.scalar(select(UserIdentity.updated_at == func.now()))
    assert touched is True


async def test_one_google_account_cannot_belong_to_two_users(session: AsyncSession) -> None:
    anna, boris = await _user(session), await _user(session)
    users = SqlUserRepository(session)
    subject = _subject()
    await users.link_identity(anna.id, GOOGLE, subject)

    with pytest.raises(IntegrityError):
        await users.link_identity(boris.id, GOOGLE, subject)


async def test_unlink_removes_only_that_users_google(session: AsyncSession) -> None:
    anna, boris = await _user(session), await _user(session)
    users = SqlUserRepository(session)
    boris_subject = _subject()
    await users.link_identity(anna.id, GOOGLE, _subject())
    await users.link_identity(boris.id, GOOGLE, boris_subject)

    await users.unlink_identity(anna.id, GOOGLE)

    assert await _identities(session) == [(boris.id, "google", boris_subject)]


async def test_unlink_without_identity_is_harmless(session: AsyncSession) -> None:
    anna = await _user(session)

    await SqlUserRepository(session).unlink_identity(anna.id, GOOGLE)

    assert await _identities(session) == []


async def test_update_profile_sets_the_three_fields_of_one_user(session: AsyncSession) -> None:
    anna = await _user(session, nickname="anna")
    boris = await _user(session)
    users = SqlUserRepository(session)

    await users.update_profile(anna.id, "Anna.New@example.org", "Аня", None)

    updated = await users.get(anna.id)
    assert updated is not None
    assert (updated.email, updated.display_name, updated.avatar_url) == (
        "Anna.New@example.org",
        "Аня",
        None,
    )
    assert updated.nickname == "anna"
    untouched = await users.get(boris.id)
    assert untouched is not None
    assert (untouched.email, untouched.display_name, untouched.avatar_url) == (
        boris.email,
        boris.display_name,
        boris.avatar_url,
    )


async def test_update_profile_cannot_take_an_email_of_another_user(session: AsyncSession) -> None:
    anna, boris = await _user(session), await _user(session)

    with pytest.raises(IntegrityError):
        await SqlUserRepository(session).update_profile(
            anna.id, boris.email.upper(), anna.display_name, None
        )


async def test_password_delete_removes_only_that_users_password(session: AsyncSession) -> None:
    anna, boris = await _user(session), await _user(session)
    passwords = SqlPasswordRepository(session)
    await passwords.set_hash(anna.id, "$argon2id$anna")
    await passwords.set_hash(boris.id, "$argon2id$boris")

    await passwords.delete(anna.id)

    assert await passwords.get_hash(anna.id) is None
    assert await passwords.get_hash(boris.id) == "$argon2id$boris"
    assert await session.scalar(select(func.count()).select_from(PasswordCredential)) == 1


async def test_password_delete_without_password_is_harmless(session: AsyncSession) -> None:
    anna = await _user(session)

    await SqlPasswordRepository(session).delete(anna.id)

    assert await SqlPasswordRepository(session).get_hash(anna.id) is None
