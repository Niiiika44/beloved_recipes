from collections.abc import Collection
from datetime import timedelta
from uuid import UUID

from sqlalchemy import delete, func, or_, select, text, update
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.modules.identity.domain.enums import EmailJobStatus, EmailPurpose
from app.modules.identity.infrastructure.models import (
    EmailJob,
    Membership,
    PasswordCredential,
    ReleasedNickname,
    User,
    Workspace,
)
from app.modules.identity.service.dto import (
    EmailJobDTO,
    MembershipDTO,
    ReleasedNicknameDTO,
    UserDTO,
)

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
            email_verified_at=user.email_verified_at,
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

    async def mark_email_verified(self, user_id: UUID) -> None:
        query = (
            update(User)
            .where(User.id == user_id, User.email_verified_at.is_(None))
            .values(email_verified_at=func.now())
        )
        await self._session.execute(query)


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

    async def purge_released(self, older_than: timedelta) -> None:
        query = delete(ReleasedNickname).where(
            ReleasedNickname.released_at < func.now() - older_than
        )
        await self._session.execute(query)


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

    async def get_hash(self, user_id: UUID) -> str | None:
        query = select(PasswordCredential.password_hash).where(
            PasswordCredential.user_id == user_id
        )
        result = await self._session.execute(query)
        return result.scalar_one_or_none()


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

    async def claim(self, batch: int, lease: timedelta) -> list[EmailJobDTO]:
        query_select = (
            select(EmailJob.id)
            .where(
                text("status = 'pending'"),
                EmailJob.available_at <= func.now(),
                or_(EmailJob.locked_until.is_(None), EmailJob.locked_until < func.now()),
            )
            .limit(batch)
            .with_for_update(skip_locked=True)
            .order_by(EmailJob.available_at)
        )
        query_update = (
            update(EmailJob)
            .where(EmailJob.id.in_(query_select))
            .values(
                attempts=EmailJob.attempts + 1,
                locked_until=func.now() + lease,
                updated_at=func.now(),
            )
            .returning(EmailJob.id, EmailJob.user_id, EmailJob.purpose, EmailJob.attempts)
        )
        result = await self._session.execute(query_update)
        email_jobs = result.all()
        return [
            EmailJobDTO(
                id=email.id, user_id=email.user_id, purpose=email.purpose, attempts=email.attempts
            )
            for email in email_jobs
        ]

    async def complete(self, job_id: UUID) -> None:
        query = delete(EmailJob).where(EmailJob.id == job_id)
        await self._session.execute(query)

    async def retry(self, job_id: UUID, delay: timedelta, error: str) -> None:
        query = (
            update(EmailJob)
            .where(EmailJob.id == job_id)
            .values(
                locked_until=None,
                last_error=error,
                available_at=func.now() + delay,
                updated_at=func.now(),
            )
        )
        await self._session.execute(query)

    async def fail(self, job_id: UUID, error: str) -> None:
        query = (
            update(EmailJob)
            .where(EmailJob.id == job_id)
            .values(
                locked_until=None,
                last_error=error,
                status=EmailJobStatus.FAILED,
                updated_at=func.now(),
            )
        )
        await self._session.execute(query)

    async def purge_failed(self, older_than: timedelta) -> None:
        query = delete(EmailJob).where(
            EmailJob.status == EmailJobStatus.FAILED,
            EmailJob.updated_at < func.now() - older_than,
        )
        await self._session.execute(query)
