from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Depends, Query, Response

from app.modules.identity.routes.dependencies import get_current_user, get_rate_limiter, get_uow
from app.modules.identity.routes.schemas import NicknameAvailabilityResponse
from app.modules.identity.service.dto import UserDTO
from app.modules.identity.service.nicknames import check_nickname
from app.modules.identity.service.ports import RateLimiter, UnitOfWork

router = APIRouter(
    prefix="/nicknames",
    tags=["nicknames"],
    responses={
        401: {"description": "Missing, expired or invalid token"},
    },
)


@router.get(
    "/availability",
    response_model=NicknameAvailabilityResponse,
    summary="Check whether a nickname can be taken",
    responses={
        422: {"description": "Query parameter nickname is missing"},
        429: {"description": "Too many nickname checks; see Retry-After"},
        503: {"description": "Session store or rate limiter is unavailable"},
    },
)
async def get_nickname_availability(
    nickname: Annotated[str, Query(description="Nickname as typed by the user")],
    response: Response,
    current_user: Annotated[UserDTO, Depends(get_current_user)],
    rate_limiter: Annotated[RateLimiter, Depends(get_rate_limiter)],
    uow: Annotated[UnitOfWork, Depends(get_uow)],
) -> NicknameAvailabilityResponse:
    response.headers["Cache-Control"] = "no-store"
    availability = await check_nickname(
        user=current_user, raw=nickname, uow=uow, limiter=rate_limiter, now=datetime.now(UTC)
    )
    return NicknameAvailabilityResponse(
        nickname=availability.nickname, available=availability.available, reason=availability.reason
    )
