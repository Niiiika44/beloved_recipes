import uuid
from datetime import UTC, datetime
from types import TracebackType
from typing import Self

import pytest

from app.core.exceptions import DependencyUnavailableError, NotAuthenticatedError
from app.modules.identity.domain.enums import WorkspaceRole
from app.modules.identity.service.auth import authenticate, get_me, logout
from app.modules.identity.service.dto import MembershipDTO, SessionDTO, UserDTO
from app.modules.identity.service.ports import SessionStore, UnitOfWork, UserRepository

TOKEN = "T" * 43
OTHER_TOKEN = "O" * 43
CREATED_AT = datetime(2026, 10, 16, 9, 0, tzinfo=UTC)


def _user(name: str = "Cook") -> UserDTO:
    return UserDTO(
        id=uuid.uuid7(),
        email=f"{name.lower()}@example.com",
        display_name=name,
        avatar_url=None,
    )


class FakeUsers:
    def __init__(
        self,
        uow: FakeUnitOfWork,
        users: dict[uuid.UUID, UserDTO],
        memberships: dict[uuid.UUID, MembershipDTO],
    ) -> None:
        self._uow = uow
        self._users = users
        self._memberships = memberships

    async def get(self, user_id: uuid.UUID) -> UserDTO | None:
        assert self._uow.active, "repository used outside the unit of work"
        return self._users.get(user_id)

    async def get_membership(self, user_id: uuid.UUID) -> MembershipDTO | None:
        assert self._uow.active, "repository used outside the unit of work"
        return self._memberships.get(user_id)


class FakeUnitOfWork:
    users: UserRepository

    def __init__(
        self,
        users: list[UserDTO] | None = None,
        memberships: dict[uuid.UUID, MembershipDTO] | None = None,
    ) -> None:
        self.active = False
        self.commits = 0
        self.users = FakeUsers(self, {user.id: user for user in users or []}, memberships or {})

    async def commit(self) -> None:
        self.commits += 1

    async def __aenter__(self) -> Self:
        self.active = True
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        self.active = False


class FakeStore:
    def __init__(
        self,
        sessions: dict[str, SessionDTO] | None = None,
        uow: FakeUnitOfWork | None = None,
        resolve_failure: Exception | None = None,
        revoke_failure: Exception | None = None,
    ) -> None:
        self.sessions = dict(sessions or {})
        self.uow = uow
        self.resolve_failure = resolve_failure
        self.revoke_failure = revoke_failure
        self.resolved: list[str] = []
        self.revoked: list[str] = []
        self.revoked_inside_uow: list[bool] = []

    async def create(self, user_id: uuid.UUID) -> str:
        raise AssertionError("scenarios under test must not create sessions")

    async def resolve(self, token: str) -> SessionDTO | None:
        self.resolved.append(token)
        if self.resolve_failure is not None:
            raise self.resolve_failure
        return self.sessions.get(token)

    async def revoke(self, token: str) -> None:
        self.revoked.append(token)
        self.revoked_inside_uow.append(self.uow is not None and self.uow.active)
        if self.revoke_failure is not None:
            raise self.revoke_failure
        self.sessions.pop(token, None)


def _session_of(user_id: uuid.UUID) -> SessionDTO:
    return SessionDTO(user_id=user_id, created_at=CREATED_AT)


def _world(
    *users: UserDTO, sessions: dict[str, SessionDTO] | None = None
) -> tuple[FakeStore, FakeUnitOfWork]:
    uow = FakeUnitOfWork(list(users))
    return FakeStore(sessions, uow), uow


def test_fakes_satisfy_ports() -> None:
    uow: UnitOfWork = FakeUnitOfWork()
    store: SessionStore = FakeStore()

    assert uow is not None
    assert store is not None


@pytest.mark.parametrize("token", [None, ""], ids=["none", "empty"])
async def test_missing_token_is_rejected_without_asking_the_store(token: str | None) -> None:
    store, uow = _world()

    with pytest.raises(NotAuthenticatedError):
        await authenticate(token, store, uow)

    assert store.resolved == []


async def test_unknown_session_is_rejected() -> None:
    store, uow = _world(_user())

    with pytest.raises(NotAuthenticatedError):
        await authenticate(TOKEN, store, uow)

    assert store.resolved == [TOKEN]
    assert store.revoked == []


async def test_valid_session_yields_its_user() -> None:
    owner = _user("Owner")
    stranger = _user("Stranger")
    store, uow = _world(stranger, owner, sessions={TOKEN: _session_of(owner.id)})

    found = await authenticate(TOKEN, store, uow)

    assert found == owner
    assert store.revoked == []


async def test_authentication_does_not_commit() -> None:
    owner = _user()
    store, uow = _world(owner, sessions={TOKEN: _session_of(owner.id)})

    await authenticate(TOKEN, store, uow)

    assert uow.commits == 0
    assert uow.active is False


async def test_session_of_deleted_user_is_revoked_and_rejected() -> None:
    store, uow = _world(_user(), sessions={TOKEN: _session_of(uuid.uuid7())})

    with pytest.raises(NotAuthenticatedError):
        await authenticate(TOKEN, store, uow)

    assert store.revoked == [TOKEN]


async def test_orphan_session_is_revoked_outside_the_unit_of_work() -> None:
    store, uow = _world(sessions={TOKEN: _session_of(uuid.uuid7())})

    with pytest.raises(NotAuthenticatedError):
        await authenticate(TOKEN, store, uow)

    assert store.revoked_inside_uow == [False]


async def _rejection_message(token: str | None, store: FakeStore, uow: FakeUnitOfWork) -> str:
    with pytest.raises(NotAuthenticatedError) as caught:
        await authenticate(token, store, uow)
    return caught.value.message


async def test_every_rejection_reads_the_same() -> None:
    orphan_owner = uuid.uuid7()
    store, uow = _world(sessions={OTHER_TOKEN: _session_of(orphan_owner)})

    messages = {
        await _rejection_message(None, store, uow),
        await _rejection_message(TOKEN, store, uow),
        await _rejection_message(OTHER_TOKEN, store, uow),
    }

    assert len(messages) == 1
    assert messages.pop()


async def test_rejection_reveals_no_identifiers() -> None:
    orphan_owner = uuid.uuid7()
    store, uow = _world(sessions={TOKEN: _session_of(orphan_owner)})

    message = await _rejection_message(TOKEN, store, uow)

    assert str(orphan_owner) not in message
    assert orphan_owner.hex not in message
    assert TOKEN not in message


async def test_store_outage_during_resolve_is_not_disguised_as_rejection() -> None:
    outage = DependencyUnavailableError("Session store is unavailable")
    uow = FakeUnitOfWork()
    store = FakeStore(uow=uow, resolve_failure=outage)

    with pytest.raises(DependencyUnavailableError) as caught:
        await authenticate(TOKEN, store, uow)

    assert caught.value is outage


async def test_store_outage_while_revoking_orphan_is_not_disguised_as_rejection() -> None:
    outage = DependencyUnavailableError("Session store is unavailable")
    uow = FakeUnitOfWork()
    store = FakeStore({TOKEN: _session_of(uuid.uuid7())}, uow, revoke_failure=outage)

    with pytest.raises(DependencyUnavailableError) as caught:
        await authenticate(TOKEN, store, uow)

    assert caught.value is outage


async def test_me_without_workspace_has_no_membership() -> None:
    user = _user()
    uow = FakeUnitOfWork([user])

    me = await get_me(user, uow)

    assert me.user == user
    assert me.membership is None


@pytest.mark.parametrize("role", list(WorkspaceRole))
async def test_me_includes_membership(role: WorkspaceRole) -> None:
    user = _user()
    membership = MembershipDTO(workspace_id=uuid.uuid7(), workspace_name="Home", role=role)
    uow = FakeUnitOfWork([user], {user.id: membership})

    me = await get_me(user, uow)

    assert me.user == user
    assert me.membership == membership


async def test_me_does_not_commit() -> None:
    user = _user()
    uow = FakeUnitOfWork([user])

    await get_me(user, uow)

    assert uow.commits == 0
    assert uow.active is False


async def test_logout_revokes_the_session() -> None:
    owner = _user()
    store, _ = _world(owner, sessions={TOKEN: _session_of(owner.id)})

    await logout(TOKEN, store)

    assert store.revoked == [TOKEN]
    assert TOKEN not in store.sessions


@pytest.mark.parametrize("token", [None, ""], ids=["none", "empty"])
async def test_logout_without_token_touches_nothing(token: str | None) -> None:
    store, _ = _world()

    await logout(token, store)

    assert store.revoked == []


async def test_store_outage_during_logout_is_reported() -> None:
    outage = DependencyUnavailableError("Session store is unavailable")
    store = FakeStore(revoke_failure=outage)

    with pytest.raises(DependencyUnavailableError) as caught:
        await logout(TOKEN, store)

    assert caught.value is outage
