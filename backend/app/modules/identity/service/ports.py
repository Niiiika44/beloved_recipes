from collections.abc import Collection
from types import TracebackType
from typing import Protocol, Self
from uuid import UUID

from app.modules.identity.domain.limits import RateLimit
from app.modules.identity.service.dto import MembershipDTO, ReleasedNicknameDTO, SessionDTO, UserDTO


class SessionStore(Protocol):
    async def create(self, user_id: UUID) -> str: ...

    async def resolve(self, token: str) -> SessionDTO | None: ...

    async def revoke(self, token: str) -> None: ...


class UserRepository(Protocol):
    async def get(self, user_id: UUID) -> UserDTO | None: ...

    async def get_for_update(self, user_id: UUID) -> UserDTO | None: ...

    async def get_membership(self, user_id: UUID) -> MembershipDTO | None: ...


class NicknameRepository(Protocol):
    async def lock(self, nicknames: Collection[str]) -> None: ...

    async def get_owner(self, nickname: str) -> UUID | None: ...

    async def get_release(self, nickname: str) -> ReleasedNicknameDTO | None: ...

    async def change(self, user_id: UUID, current: str | None, new: str) -> None: ...


class UnitOfWork(Protocol):
    users: UserRepository
    nicknames: NicknameRepository

    async def commit(self) -> None: ...

    async def __aenter__(self) -> Self: ...

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None: ...


class RateLimiter(Protocol):
    async def hit(self, key: str, rule: RateLimit) -> int | None: ...
