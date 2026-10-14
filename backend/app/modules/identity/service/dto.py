from dataclasses import dataclass
from datetime import datetime
from uuid import UUID

from app.modules.identity.domain.enums import WorkspaceRole


@dataclass(frozen=True, slots=True)
class SessionDTO:
    user_id: UUID
    created_at: datetime


@dataclass(frozen=True, slots=True)
class UserDTO:
    id: UUID
    email: str
    display_name: str
    avatar_url: str | None


@dataclass(frozen=True, slots=True)
class MembershipDTO:
    workspace_id: UUID
    workspace_name: str
    role: WorkspaceRole


@dataclass(frozen=True, slots=True)
class MeDTO:
    user: UserDTO
    membership: MembershipDTO | None
