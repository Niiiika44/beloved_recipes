from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from app.modules.identity.domain.enums import WorkspaceRole


class WorkspaceResponse(BaseModel):
    id: UUID = Field(..., description="Unique workspace identifier")
    name: str = Field(..., description="Workspace name")
    role: WorkspaceRole = Field(..., description="Role in the workspace")


class MeResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: UUID = Field(..., description="Unique user identifier")
    email: str = Field(..., description="Email address")
    display_name: str = Field(..., description="Displayed name of the user")
    avatar_url: str | None = Field(..., description="Path to the avatar of the user")
    workspace: WorkspaceResponse | None = Field(..., description="User's workspace")
