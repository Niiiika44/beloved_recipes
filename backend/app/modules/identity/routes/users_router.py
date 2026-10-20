from typing import Annotated

from fastapi import APIRouter, Depends, Response

from app.modules.identity.routes.dependencies import get_current_user, get_uow
from app.modules.identity.routes.schemas import MeResponse, WorkspaceResponse
from app.modules.identity.service.auth import get_me
from app.modules.identity.service.dto import UserDTO
from app.modules.identity.service.ports import UnitOfWork

router = APIRouter(
    prefix="/users",
    tags=["users"],
    responses={
        401: {"description": "Missing, expired or invalid token"},
    },
)


@router.get(
    "/me",
    response_model=MeResponse,
    summary="Get the current user",
    responses={503: {"description": "Session store is unavailable"}},
)
async def get_my_identity(
    response: Response,
    current_user: Annotated[UserDTO, Depends(get_current_user)],
    uow: Annotated[UnitOfWork, Depends(get_uow)],
) -> MeResponse:
    me = await get_me(user=current_user, uow=uow)
    response.headers["Cache-Control"] = "no-store"
    return MeResponse(
        id=me.user.id,
        email=me.user.email,
        display_name=me.user.display_name,
        avatar_url=me.user.avatar_url,
        workspace=WorkspaceResponse(
            id=me.membership.workspace_id,
            name=me.membership.workspace_name,
            role=me.membership.role,
        )
        if me.membership is not None
        else None,
    )
