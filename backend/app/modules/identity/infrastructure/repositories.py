from collections.abc import Collection
from uuid import UUID

from sqlalchemy import delete, func, select, text, update
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.modules.identity.domain.enums import EmailPurpose
from app.modules.identity.infrastructure.models import (
    EmailJob,
    Membership,
    PasswordCredential,
    ReleasedNickname,
    User,
    Workspace,
)
from app.modules.identity.service.dto import MembershipDTO, ReleasedNicknameDTO, UserDTO

NICKNAME_LOCK_SPACE = 1


class SqlUserRepository:
    def __init__(self, session: AsyncSession):
        self._session = session

    async def get(self, user_id: UUID) -> UserDTO | None:
        return await self._fetch(user_id, for_update=False)

    async def get_for_update(self, user_id: UUID) -> UserDTO | None:
        return await self._fetch(user_id, for_update=True)

    def _to_dto(self, user: User | None) -> UserDTO | None:
        if user is None:
            return None
        return UserDTO(
            id=user.id,
            email=user.email,
            display_name=user.display_name,
            avatar_url=user.avatar_url,
            nickname=user.nickname,
        )

    async def _fetch(self, user_id: UUID, *, for_update: bool) -> UserDTO | None:
        query = select(User).where(User.id == user_id)
        if for_update:
            query = query.with_for_update()
        result = await self._session.execute(query)
        user = result.scalar_one_or_none()
        return self._to_dto(user)

    async def get_membership(self, user_id: UUID) -> MembershipDTO | None:
        query = (
            select(Membership.workspace_id, Membership.role, Workspace.name)
            .join(Workspace, onclause=Workspace.id == Membership.workspace_id)
            .where(Membership.user_id == user_id)
        )
        result = await self._session.execute(query)
        membership = result.one_or_none()
        if membership is None:
            return None
        return MembershipDTO(
            workspace_id=membership.workspace_id,
            workspace_name=membership.name,
            role=membership.role,
        )

    async def create(self, email: str, display_name: str) -> UUID | None:
        query = (
            insert(User)
            .values(email=email, display_name=display_name)
            .on_conflict_do_nothing(index_elements=[func.lower(User.email)])
            .returning(User.id)
        )
        result = await self._session.execute(query)
        return result.scalar_one_or_none()

    async def find_by_email(self, email: str) -> UserDTO | None:
        query = select(User).where(func.lower(User.email) == func.lower(email))
        result = await self._session.execute(query)
        user = result.scalar_one_or_none()
        return self._to_dto(user)


class SqlNicknameRepository:
    def __init__(self, session: AsyncSession):
        self._session = session

    async def lock(self, nicknames: Collection[str]) -> None:
        if not nicknames:
            return
        query_nicknames = select(*(func.hashtext(n) for n in nicknames))
        result = await self._session.execute(query_nicknames)
        for key in sorted(result.one()):
            query = select(func.pg_advisory_xact_lock(NICKNAME_LOCK_SPACE, key))
            await self._session.execute(query)

    async def get_owner(self, nickname: str) -> UUID | None:
        query = select(User.id).where(User.nickname == nickname)
        result = await self._session.execute(query)
        return result.scalar_one_or_none()

    async def get_release(self, nickname: str) -> ReleasedNicknameDTO | None:
        query = select(ReleasedNickname).where(ReleasedNickname.nickname == nickname)
        result = await self._session.execute(query)
        released_nickname = result.scalar_one_or_none()
        if released_nickname is None:
            return None
        return ReleasedNicknameDTO(
            released_by=released_nickname.released_by, released_at=released_nickname.released_at
        )

    async def change(self, user_id: UUID, current: str | None, new: str) -> None:
        query_user_update = update(User).where(User.id == user_id).values(nickname=new)
        await self._session.execute(query_user_update)
        query_quarantine = delete(ReleasedNickname).where(ReleasedNickname.nickname == new)
        await self._session.execute(query_quarantine)
        if current is None:
            return
        query_quarantine_update = (
            insert(ReleasedNickname)
            .values(
                nickname=current,
                released_by=user_id,
                released_at=func.now(),
            )
            .on_conflict_do_update(
                index_elements=["nickname"],
                set_={"released_at": func.now(), "released_by": user_id},
            )
        )
        await self._session.execute(query_quarantine_update)


class SqlPasswordRepository:
    def __init__(self, session: AsyncSession):
        self._session = session

    async def set_hash(self, user_id: UUID, password_hash: str) -> None:
        query = (
            insert(PasswordCredential)
            .values(user_id=user_id, password_hash=password_hash)
            .on_conflict_do_update(
                index_elements=[PasswordCredential.user_id],
                set_={"password_hash": password_hash, "updated_at": func.now()},
            )
        )
        await self._session.execute(query)


class SqlEmailJobRepository:
    def __init__(self, session: AsyncSession):
        self._session = session

    async def enqueue(self, purpose: EmailPurpose, user_id: UUID) -> None:
        query = (
            insert(EmailJob)
            .values(user_id=user_id, purpose=purpose)
            .on_conflict_do_nothing(
                index_elements=[EmailJob.user_id, EmailJob.purpose],
                index_where=text("status = 'pending'"),
            )
        )
        await self._session.execute(query)
