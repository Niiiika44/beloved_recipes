from types import TracebackType
from typing import Self

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.modules.identity.infrastructure.repositories import (
    SqlEmailJobRepository,
    SqlNicknameRepository,
    SqlPasswordRepository,
    SqlUserRepository,
)
from app.modules.identity.service.ports import (
    EmailJobRepository,
    NicknameRepository,
    PasswordRepository,
    UserRepository,
)


class SqlAlchemyUnitOfWork:
    users: UserRepository
    nicknames: NicknameRepository
    passwords: PasswordRepository
    email_jobs: EmailJobRepository
    _session: AsyncSession
    _committed: bool

    def __init__(self, session_factory: async_sessionmaker[AsyncSession]):
        self._session_factory = session_factory

    async def __aenter__(self) -> Self:
        self._session = self._session_factory()
        self.users = SqlUserRepository(self._session)
        self.nicknames = SqlNicknameRepository(self._session)
        self.passwords = SqlPasswordRepository(self._session)
        self.email_jobs = SqlEmailJobRepository(self._session)
        self._committed = False
        return self

    async def commit(self) -> None:
        await self._session.commit()
        self._committed = True

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        try:
            if not self._committed:
                await self._session.rollback()
        finally:
            await self._session.close()
