from typing import Annotated

from fastapi import APIRouter, Depends, Request, Response, status

from app.core.config import Settings, get_settings
from app.modules.identity.routes.cookies import cookie_info, set_session_cookie
from app.modules.identity.routes.dependencies import (
    get_one_time_token_store,
    get_password_login_service,
    get_rate_limiter,
    get_registration_service,
    get_secret,
    get_security_events,
    get_session_store,
    get_uow,
)
from app.modules.identity.routes.schemas import (
    ConfirmEmailRequest,
    LoginRequest,
    RegisterRequest,
    ResendConfirmationRequest,
)
from app.modules.identity.service.auth import logout
from app.modules.identity.service.dto import LoginDTO, RegistrationDTO, ResendConfirmationDTO
from app.modules.identity.service.email_confirmation import confirm_email, resend_confirmation
from app.modules.identity.service.password_login import PasswordLoginService
from app.modules.identity.service.ports import (
    OneTimeTokenStore,
    RateLimiter,
    SecurityEvents,
    SessionStore,
    UnitOfWork,
)
from app.modules.identity.service.registration import RegistrationService

router = APIRouter(
    prefix="/auth",
    tags=["auth"],
)


@router.post(
    "/login",
    status_code=status.HTTP_204_NO_CONTENT,
    response_class=Response,
    summary="Log in with email and password",
    responses={
        401: {"description": "Wrong email or password, or a password of invalid format"},
        403: {"description": "Email is not confirmed yet"},
        422: {"description": "Malformed request body"},
        429: {"description": "Too many login attempts; see Retry-After"},
        503: {"description": "Rate limiter, database or session store is unavailable"},
    },
)
async def do_login(
    body: LoginRequest,
    request: Request,
    response: Response,
    settings: Annotated[Settings, Depends(get_settings)],
    service: Annotated[PasswordLoginService, Depends(get_password_login_service)],
) -> None:
    response.headers["Cache-Control"] = "no-store"
    token = request.cookies.get(settings.session.cookie_name)
    client_ip = request.client.host if request.client else None
    login = LoginDTO(
        email=body.email, password=body.password, client_ip=client_ip, current_token=token
    )
    new_token = await service.login(login)
    set_session_cookie(response, settings, new_token)


@router.post(
    "/logout",
    status_code=status.HTTP_204_NO_CONTENT,
    response_class=Response,
    summary="Log out the current user",
    responses={503: {"description": "Session store is unavailable"}},
)
async def do_logout(
    request: Request,
    response: Response,
    settings: Annotated[Settings, Depends(get_settings)],
    store: Annotated[SessionStore, Depends(get_session_store)],
    events: Annotated[SecurityEvents, Depends(get_security_events)],
) -> None:
    token = request.cookies.get(settings.session.cookie_name)
    await logout(token=token, store=store, events=events)
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


@router.post(
    "/email/confirm",
    status_code=status.HTTP_204_NO_CONTENT,
    response_class=Response,
    summary="Confirm the email with the token from the link",
    responses={
        422: {"description": "Token is invalid, expired or already used"},
        503: {"description": "Token store or database is unavailable"},
    },
)
async def confirm_email_address(
    body: ConfirmEmailRequest,
    response: Response,
    tokens: Annotated[OneTimeTokenStore, Depends(get_one_time_token_store)],
    uow: Annotated[UnitOfWork, Depends(get_uow)],
    events: Annotated[SecurityEvents, Depends(get_security_events)],
) -> None:
    response.headers["Cache-Control"] = "no-store"
    await confirm_email(token=body.token, tokens=tokens, uow=uow, events=events)


@router.post(
    "/email/resend",
    status_code=status.HTTP_202_ACCEPTED,
    response_class=Response,
    summary="Send the confirmation email again",
    responses={
        422: {"description": "Invalid email"},
        429: {"description": "Too many requests; see Retry-After"},
        503: {"description": "Rate limiter or database is unavailable"},
    },
)
async def resend_confirmation_email(
    body: ResendConfirmationRequest,
    request: Request,
    response: Response,
    uow: Annotated[UnitOfWork, Depends(get_uow)],
    limiter: Annotated[RateLimiter, Depends(get_rate_limiter)],
    secret: Annotated[bytes, Depends(get_secret)],
    events: Annotated[SecurityEvents, Depends(get_security_events)],
) -> None:
    response.headers["Cache-Control"] = "no-store"
    client_ip = request.client.host if request.client else None
    await resend_confirmation(
        request=ResendConfirmationDTO(email=body.email, client_ip=client_ip),
        uow=uow,
        limiter=limiter,
        secret=secret,
        events=events,
    )
