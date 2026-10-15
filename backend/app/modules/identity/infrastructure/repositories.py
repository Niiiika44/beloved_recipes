from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.modules.identity.infrastructure.models import Membership, User, Workspace
from app.modules.identity.service.dto import MembershipDTO, UserDTO


class SqlUserRepository:
    def __init__(self, session: AsyncSession):
        self._session = session

    async def get(self, user_id: UUID) -> UserDTO | None:
        query = select(User).where(User.id == user_id)
        result = await self._session.execute(query)
        user = result.scalar_one_or_none()
        if user is None:
            return None
        return UserDTO(
            id=user.id, email=user.email, display_name=user.display_name, avatar_url=user.avatar_url
        )

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
