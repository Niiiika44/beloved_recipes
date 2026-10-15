import uuid
from collections.abc import AsyncIterator, Iterator
from pathlib import Path
from typing import Any

import pytest
from alembic.config import Config
from sqlalchemy import event, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from alembic import command
from app.core.db import dispose_engine, get_engine, get_session_factory
from app.modules.identity.domain.enums import WorkspaceRole
from app.modules.identity.infrastructure.models import Membership, User, Workspace
from app.modules.identity.infrastructure.repositories import SqlUserRepository
from app.modules.identity.service.dto import MembershipDTO, UserDTO

ALEMBIC_INI = Path(__file__).resolve().parents[1] / "alembic.ini"


@pytest.fixture(scope="module")
def migrated(_point_at_container: None) -> Iterator[None]:
    config = Config(str(ALEMBIC_INI))
    command.upgrade(config, "head")

    yield

    command.downgrade(config, "base")


@pytest.fixture
async def session(migrated: None) -> AsyncIterator[AsyncSession]:
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
        "google_sub": f"sub-{suffix}",
        "display_name": f"Cook {suffix}",
        "avatar_url": f"https://example.com/{suffix}.png",
    }
    user = User(**(values | overrides))
    session.add(user)
    await session.flush()
    return user


async def _workspace_with(
    session: AsyncSession, member: User, role: WorkspaceRole, name: str = "Home kitchen"
) -> Workspace:
    workspace = Workspace(name=name, owner_id=member.id)
    session.add(workspace)
    await session.flush()
    session.add(Membership(user_id=member.id, workspace_id=workspace.id, role=role))
    await session.flush()
    return workspace


def _count_statements(session: AsyncSession) -> list[str]:
    statements: list[str] = []

    def record(*args: Any) -> None:
        statements.append(args[2])

    event.listen(session.bind.sync_engine, "before_cursor_execute", record)
    return statements


async def test_get_returns_user_dto(session: AsyncSession) -> None:
    user = await _user(session)

    found = await SqlUserRepository(session).get(user.id)

    assert found == UserDTO(
        id=user.id,
        email=user.email,
        display_name=user.display_name,
        avatar_url=user.avatar_url,
    )


async def test_get_returns_dto_not_orm_object(session: AsyncSession) -> None:
    user = await _user(session)

    found = await SqlUserRepository(session).get(user.id)

    assert type(found) is UserDTO


async def test_get_keeps_missing_avatar_as_none(session: AsyncSession) -> None:
    user = await _user(session, avatar_url=None)

    found = await SqlUserRepository(session).get(user.id)

    assert found is not None
    assert found.avatar_url is None


async def test_get_unknown_user_returns_none(session: AsyncSession) -> None:
    await _user(session)

    assert await SqlUserRepository(session).get(uuid.uuid7()) is None


async def test_get_picks_the_requested_user(session: AsyncSession) -> None:
    await _user(session)
    wanted = await _user(session)
    await _user(session)

    found = await SqlUserRepository(session).get(wanted.id)

    assert found is not None
    assert found.id == wanted.id
    assert found.email == wanted.email


async def test_user_without_workspace_has_no_membership(session: AsyncSession) -> None:
    user = await _user(session)

    assert await SqlUserRepository(session).get_membership(user.id) is None


@pytest.mark.parametrize("role", list(WorkspaceRole))
async def test_membership_carries_workspace_and_role(
    session: AsyncSession, role: WorkspaceRole
) -> None:
    user = await _user(session)
    workspace = await _workspace_with(session, user, role, name="Sunday dinners")

    found = await SqlUserRepository(session).get_membership(user.id)

    assert found == MembershipDTO(
        workspace_id=workspace.id, workspace_name="Sunday dinners", role=role
    )
    assert type(found) is MembershipDTO
    assert isinstance(found.role, WorkspaceRole)


async def test_membership_belongs_to_the_requested_user(session: AsyncSession) -> None:
    neighbour = await _user(session)
    await _workspace_with(session, neighbour, WorkspaceRole.OWNER, name="Neighbour")
    user = await _user(session)
    own = await _workspace_with(session, user, WorkspaceRole.OWNER, name="Own")

    found = await SqlUserRepository(session).get_membership(user.id)

    assert found is not None
    assert found.workspace_id == own.id
    assert found.workspace_name == "Own"


async def test_member_sees_workspace_owned_by_someone_else(session: AsyncSession) -> None:
    owner = await _user(session)
    workspace = await _workspace_with(session, owner, WorkspaceRole.OWNER, name="Shared")
    member = await _user(session)
    session.add(Membership(user_id=member.id, workspace_id=workspace.id, role=WorkspaceRole.MEMBER))
    await session.flush()

    found = await SqlUserRepository(session).get_membership(member.id)

    assert found == MembershipDTO(
        workspace_id=workspace.id, workspace_name="Shared", role=WorkspaceRole.MEMBER
    )


async def test_membership_is_read_in_one_query(session: AsyncSession) -> None:
    user = await _user(session)
    await _workspace_with(session, user, WorkspaceRole.MEMBER)
    session.expunge_all()
    statements = _count_statements(session)

    await SqlUserRepository(session).get_membership(user.id)

    assert len(statements) == 1


async def test_repository_never_commits(session: AsyncSession) -> None:
    user = await _user(session)
    await _workspace_with(session, user, WorkspaceRole.OWNER)
    repository = SqlUserRepository(session)

    await repository.get(user.id)
    await repository.get_membership(user.id)
    await session.rollback()

    remaining = await session.scalar(select(func.count()).select_from(User))
    assert remaining == 0
