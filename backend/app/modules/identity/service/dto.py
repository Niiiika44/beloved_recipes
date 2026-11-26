from dataclasses import dataclass, field
from datetime import datetime
from uuid import UUID

from app.modules.identity.domain.enums import EmailPurpose, WorkspaceRole
from app.modules.identity.domain.oidc import ProviderRejectionReason


@dataclass(frozen=True, slots=True)
class SessionDTO:
    user_id: UUID
    created_at: datetime
    credentials_version: int


@dataclass(frozen=True, slots=True)
class UserDTO:
    id: UUID
    nickname: str | None
    email: str
    display_name: str
    avatar_url: str | None
    email_verified_at: datetime | None
    credentials_version: int


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


@dataclass(frozen=True, slots=True)
class LoginDTO:
    email: str
    password: str = field(repr=False)
    client_ip: str | None
    current_token: str | None = field(repr=False)


@dataclass(frozen=True, slots=True)
class PasswordCheckDTO:
    matches: bool
    needs_rehash: bool


@dataclass(frozen=True, slots=True)
class OneTimeTokenDTO:
    user_id: UUID
    credentials_version: int


@dataclass(frozen=True, slots=True)
class PasswordResetRequestDTO:
    email: str
    client_ip: str | None


@dataclass(frozen=True, slots=True)
class PasswordResetDTO:
    token: str = field(repr=False)
    password: str = field(repr=False)


@dataclass(frozen=True, slots=True)
class PasswordChangeDTO:
    current: str = field(repr=False)
    new: str = field(repr=False)


@dataclass(frozen=True, slots=True)
class OidcIdentityDTO:
    subject: str
    email: str
    email_verified: bool
    name: str
    picture: str | None
    nonce: str


@dataclass(frozen=True, slots=True)
class ProviderRejectionDTO:
    reason: ProviderRejectionReason


@dataclass(frozen=True, slots=True)
class PendingLoginDTO:
    code_verifier: str = field(repr=False)
    nonce: str
    next: str
    browser_binding_hash: str


@dataclass(frozen=True, slots=True)
class GoogleLoginStartDTO:
    authorization_url: str
    browser_binding: str = field(repr=False)


@dataclass(frozen=True, slots=True)
class GoogleCallbackDTO:
    code: str = field(repr=False)
    state: str
    browser_binding: str | None = field(repr=False)
    current_token: str | None = field(repr=False)
    client_ip: str | None


@dataclass(frozen=True, slots=True)
class GoogleLoginResultDTO:
    token: str = field(repr=False)
    next: str
