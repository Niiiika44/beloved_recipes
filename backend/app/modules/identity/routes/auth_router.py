from typing import Annotated

from fastapi import APIRouter, Depends, Request, Response, status

from app.core.config import Settings, get_settings
from app.modules.identity.routes.cookies import cookie_info
from app.modules.identity.routes.dependencies import get_registration_service, get_session_store
from app.modules.identity.routes.schemas import RegisterRequest
from app.modules.identity.service.auth import logout
from app.modules.identity.service.dto import RegistrationDTO
from app.modules.identity.service.ports import SessionStore
from app.modules.identity.service.registration import RegistrationService

router = APIRouter(
    prefix="/auth",
    tags=["auth"],
)


@router.post(
    "/logout",
    status_code=status.HTTP_204_NO_CONTENT,
    response_model=None,
    summary="Log out the current user",
    responses={503: {"description": "Session store is unavailable"}},
)
async def do_logout(
    request: Request,
    response: Response,
    settings: Annotated[Settings, Depends(get_settings)],
    store: Annotated[SessionStore, Depends(get_session_store)],
) -> None:
    token = request.cookies.get(settings.session.cookie_name)
    await logout(token=token, store=store)
    cookie = cookie_info(settings.session.cookie_name, settings.session.cookie_secure)
    response.set_cookie(**cookie, max_age=0)


@router.post(
    "/register",
    status_code=status.HTTP_202_ACCEPTED,
    response_class=Response,
    summary="Register with email and password",
    responses={
        422: {"description": "Invalid email, password or display name"},
        429: {"description": "Too many registrations; see Retry-After"},
        503: {"description": "Rate limiter or database is unavailable"},
    },
)
async def register(
    body: RegisterRequest,
    request: Request,
    response: Response,
    service: Annotated[RegistrationService, Depends(get_registration_service)],
) -> None:
    client_ip = request.client.host if request.client else None
    response.headers["Cache-Control"] = "no-store"
    await service.register(
        RegistrationDTO(
            email=body.email,
            password=body.password,
            display_name=body.display_name,
            client_ip=client_ip,
        )
    )
