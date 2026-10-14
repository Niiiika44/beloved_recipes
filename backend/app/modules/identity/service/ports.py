from types import TracebackType
from typing import Protocol, Self
from uuid import UUID

from app.modules.identity.service.dto import MembershipDTO, SessionDTO, UserDTO


class SessionStore(Protocol):
    async def create(self, user_id: UUID) -> str: ...

    async def resolve(self, token: str) -> SessionDTO | None: ...

    async def revoke(self, token: str) -> None: ...


class UserRepository(Protocol):
    async def get(self, user_id: UUID) -> UserDTO | None: ...

    async def get_membership(self, user_id: UUID) -> MembershipDTO | None: ...


class UnitOfWork(Protocol):
    users: UserRepository

    async def commit(self) -> None: ...

    async def __aenter__(self) -> Self: ...

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None: ...
