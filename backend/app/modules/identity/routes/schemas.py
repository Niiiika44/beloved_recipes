from uuid import UUID

from pydantic import BaseModel, ConfigDict, EmailStr, Field

from app.modules.identity.domain.enums import WorkspaceRole


class WorkspaceResponse(BaseModel):
    id: UUID = Field(..., description="Unique workspace identifier")
    name: str = Field(..., description="Workspace name")
    role: WorkspaceRole = Field(..., description="Role in the workspace")


class MeResponse(BaseModel):
    id: UUID = Field(..., description="Unique user identifier")
    email: str = Field(..., description="Email address")
    display_name: str = Field(..., description="Displayed name of the user")
    nickname: str | None = Field(..., description="User's nickname")
    avatar_url: str | None = Field(..., description="User avatar url")
    workspace: WorkspaceResponse | None = Field(..., description="User's workspace")


class NicknameAvailabilityResponse(BaseModel):
    nickname: str | None = Field(..., description="Normalized nickname or null if incorrect format")
    available: bool = Field(..., description="Is nickname available to be taken")
    reason: str | None = Field(..., description="Reason of being unavailable")


class UpdateMeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    nickname: str = Field(default="", description="User's nickname")


class RegisterRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    email: EmailStr = Field(..., description="Email to sign in with")
    password: str = Field(..., description="Password, 8 to 128 characters")
    display_name: str = Field(..., description="Name shown to other users")


class LoginRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    email: EmailStr = Field(..., description="Email to log in with")
    password: str = Field(..., description="Password to log in with")


class ConfirmEmailRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    token: str = Field(..., description="Token from the confirmation link")


class ResendConfirmationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    email: EmailStr = Field(..., description="Email to send the confirmation to again")
