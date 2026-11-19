from collections.abc import Collection
from types import TracebackType
from typing import Protocol, Self
from uuid import UUID

from app.modules.identity.domain.enums import EmailPurpose
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

    async def create(self, email: str, display_name: str) -> UUID | None: ...

    async def find_by_email(self, email: str) -> UserDTO | None: ...


class NicknameRepository(Protocol):
    async def lock(self, nicknames: Collection[str]) -> None: ...

    async def get_owner(self, nickname: str) -> UUID | None: ...

    async def get_release(self, nickname: str) -> ReleasedNicknameDTO | None: ...

    async def change(self, user_id: UUID, current: str | None, new: str) -> None: ...


class PasswordRepository(Protocol):
    async def set_hash(self, user_id: UUID, password_hash: str) -> None: ...


class EmailJobRepository(Protocol):
    async def enqueue(self, purpose: EmailPurpose, user_id: UUID) -> None: ...


class UnitOfWork(Protocol):
    users: UserRepository
    nicknames: NicknameRepository
    passwords: PasswordRepository
    email_jobs: EmailJobRepository

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


class PasswordHasher(Protocol):
    async def hash_password(self, password: str) -> str: ...


class BreachedPasswordChecker(Protocol):
    async def is_breached(self, password: str) -> bool | None: ...


class SecurityEvents(Protocol):
    def rate_limited(self, action: str, scope: str) -> None: ...

    def breach_check_unavailable(self) -> None: ...
