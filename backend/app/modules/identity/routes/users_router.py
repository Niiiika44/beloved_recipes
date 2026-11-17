from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Depends, Response

from app.modules.identity.routes.dependencies import get_current_user, get_rate_limiter, get_uow
from app.modules.identity.routes.schemas import MeResponse, UpdateMeRequest, WorkspaceResponse
from app.modules.identity.service.dto import ProfileChangesDTO, UserDTO
from app.modules.identity.service.ports import RateLimiter, UnitOfWork
from app.modules.identity.service.profile import get_me, update_me

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
        nickname=me.user.nickname,
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


@router.patch(
    "/me",
    response_model=MeResponse,
    summary="Edit the current user info",
    responses={
        409: {"description": "Nickname is already taken"},
        422: {"description": "Invalid request body or nickname"},
        429: {"description": "Too many nickname changes; see Retry-After"},
        503: {"description": "Session store or rate limiter is unavailable"},
    },
)
async def patch_me(
    request: UpdateMeRequest,
    response: Response,
    current_user: Annotated[UserDTO, Depends(get_current_user)],
    rate_limiter: Annotated[RateLimiter, Depends(get_rate_limiter)],
    uow: Annotated[UnitOfWork, Depends(get_uow)],
) -> MeResponse:
    response.headers["Cache-Control"] = "no-store"
    changes = ProfileChangesDTO(**request.model_dump(exclude_unset=True))
    me = await update_me(
        user=current_user, changes=changes, uow=uow, limiter=rate_limiter, now=datetime.now(UTC)
    )
    return MeResponse(
        id=me.user.id,
        nickname=me.user.nickname,
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
