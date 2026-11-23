from dataclasses import dataclass, field
from datetime import datetime
from uuid import UUID

from app.modules.identity.domain.enums import EmailPurpose, WorkspaceRole


@dataclass(frozen=True, slots=True)
class SessionDTO:
    user_id: UUID
    created_at: datetime


@dataclass(frozen=True, slots=True)
class UserDTO:
    id: UUID
    nickname: str | None
    email: str
    display_name: str
    avatar_url: str | None
    email_verified_at: datetime | None


@dataclass(frozen=True, slots=True)
class MembershipDTO:
    workspace_id: UUID
    workspace_name: str
    role: WorkspaceRole


@dataclass(frozen=True, slots=True)
class MeDTO:
    user: UserDTO
    membership: MembershipDTO | None


@dataclass(frozen=True, slots=True)
class ProfileChangesDTO:
    nickname: str | None = None


@dataclass(frozen=True, slots=True)
class ReleasedNicknameDTO:
    released_by: UUID | None
    released_at: datetime


@dataclass(frozen=True, slots=True)
class NicknameAvailabilityDTO:
    nickname: str | None
    available: bool
    reason: str | None


@dataclass(frozen=True, slots=True)
class RegistrationDTO:
    email: str
    password: str = field(repr=False)
    display_name: str
    client_ip: str | None


@dataclass(frozen=True, slots=True)
class EmailJobDTO:
    id: UUID
    user_id: UUID
    purpose: EmailPurpose
    attempts: int


@dataclass(frozen=True, slots=True)
class ResendConfirmationDTO:
    email: str
    client_ip: str | None
