import uuid
from collections.abc import Collection, Iterable
from types import TracebackType
from typing import Self

from app.modules.identity.domain.limits import RateLimit
from app.modules.identity.service.dto import MembershipDTO, ReleasedNicknameDTO, UserDTO
from app.modules.identity.service.ports import NicknameRepository, UserRepository


def make_user(name: str = "Cook", nickname: str | None = None) -> UserDTO:
    return UserDTO(
        id=uuid.uuid7(),
        nickname=nickname,
        email=f"{name.lower()}@example.com",
        display_name=name,
        avatar_url=None,
    )


class FakeUsers:
    def __init__(self, uow: FakeUnitOfWork) -> None:
        self._uow = uow

    async def get(self, user_id: uuid.UUID) -> UserDTO | None:
        self._uow.record("get")
        return self._uow.stored.get(user_id)

    async def get_for_update(self, user_id: uuid.UUID) -> UserDTO | None:
        self._uow.record("get_for_update")
        return self._uow.stored.get(user_id)

    async def get_membership(self, user_id: uuid.UUID) -> MembershipDTO | None:
        self._uow.record("get_membership")
        return self._uow.memberships.get(user_id)


class FakeNicknames:
    def __init__(self, uow: FakeUnitOfWork) -> None:
        self._uow = uow

    async def lock(self, nicknames: Collection[str]) -> None:
        self._uow.record("lock")
        self._uow.locked.append(sorted(nicknames))

    async def get_owner(self, nickname: str) -> uuid.UUID | None:
        self._uow.record("get_owner")
        owners = [user.id for user in self._uow.stored.values() if user.nickname == nickname]
        return owners[0] if owners else None

    async def get_release(self, nickname: str) -> ReleasedNicknameDTO | None:
        self._uow.record("get_release")
        return self._uow.releases.get(nickname)

    async def change(self, user_id: uuid.UUID, current: str | None, new: str) -> None:
        self._uow.record("change")
        self._uow.changes.append((user_id, current, new))


class FakeUnitOfWork:
    users: UserRepository
    nicknames: NicknameRepository

    def __init__(
        self,
        users: Iterable[UserDTO] = (),
        memberships: dict[uuid.UUID, MembershipDTO] | None = None,
        releases: dict[str, ReleasedNicknameDTO] | None = None,
    ) -> None:
        self.stored = {user.id: user for user in users}
        self.memberships = dict(memberships or {})
        self.releases = dict(releases or {})
        self.active = False
        self.commits = 0
        self.calls: list[str] = []
        self.locked: list[list[str]] = []
        self.changes: list[tuple[uuid.UUID, str | None, str]] = []
        self.users = FakeUsers(self)
        self.nicknames = FakeNicknames(self)

    def record(self, call: str) -> None:
        assert self.active, f"{call} used outside the unit of work"
        self.calls.append(call)

    async def commit(self) -> None:
        self.record("commit")
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


class FakeLimiter:
    def __init__(
        self,
        uow: FakeUnitOfWork | None = None,
        retry_after: int | None = None,
        failure: Exception | None = None,
    ) -> None:
        self.uow = uow
        self.retry_after = retry_after
        self.failure = failure
        self.hits: list[tuple[str, RateLimit]] = []
        self.hit_inside_uow: list[bool] = []

    async def hit(self, key: str, rule: RateLimit) -> int | None:
        self.hits.append((key, rule))
        if self.uow is not None:
            self.uow.calls.append("hit")
            self.hit_inside_uow.append(self.uow.active)
        if self.failure is not None:
            raise self.failure
        return self.retry_after
