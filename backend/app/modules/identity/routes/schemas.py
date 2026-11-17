from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

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
