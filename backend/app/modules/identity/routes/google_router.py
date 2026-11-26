from typing import Annotated
from urllib.parse import urlencode

import structlog
from fastapi import APIRouter, Depends, Query, Request, Response, status
from fastapi.responses import RedirectResponse

from app.api.paths import (
    API_V1_PREFIX,
    GOOGLE_CALLBACK_PATH,
    GOOGLE_LOGIN_PATH,
    GOOGLE_NOT_ME_PATH,
    GOOGLE_PATH_PREFIX,
    LOGIN_PAGE_PATH,
)
from app.core.config import Settings, get_settings
from app.core.exceptions import DependencyUnavailableError
from app.modules.identity.domain.oidc import LOGIN_STATE_TTL
from app.modules.identity.routes.cookies import set_session_cookie
from app.modules.identity.routes.dependencies import (
    get_google_login_service,
    get_login_state_store,
    get_oidc_provider,
    get_one_time_token_store,
    get_rate_limiter,
    get_security_events,
    get_uow,
)
from app.modules.identity.routes.schemas import GoogleNotMeRequest
from app.modules.identity.service.dto import GoogleCallbackDTO
from app.modules.identity.service.exceptions import GoogleRejectedError
from app.modules.identity.service.google_login import (
    GoogleLoginService,
    disown_google_login,
    start_google_login,
)
from app.modules.identity.service.ports import (
    LoginStateStore,
    OidcProvider,
    OneTimeTokenStore,
    RateLimiter,
    SecurityEvents,
    UnitOfWork,
)

BINDING_COOKIE = "oauth_binding"
logger = structlog.get_logger(__name__)
BINDING_COOKIE_PATH = API_V1_PREFIX + GOOGLE_PATH_PREFIX

router = APIRouter(tags=["auth"])


def _to_login_page(error: str) -> RedirectResponse:
    response = RedirectResponse(
        f"{LOGIN_PAGE_PATH}?{urlencode({'error': error})}", status_code=status.HTTP_303_SEE_OTHER
    )
    response.headers["Cache-Control"] = "no-store"
    return response


def _drop_binding(response: Response, settings: Settings) -> None:
    response.set_cookie(
        key=BINDING_COOKIE,
        value="",
        max_age=0,
        path=BINDING_COOKIE_PATH,
        secure=settings.session.cookie_secure,
        httponly=True,
        samesite="lax",
    )


@router.get(
    GOOGLE_LOGIN_PATH,
    status_code=status.HTTP_302_FOUND,
    response_class=RedirectResponse,
    summary="Start signing in with Google",
    responses={
        302: {"description": "Redirect to Google; sets the short-lived browser binding cookie"},
        303: {"description": "Redirect to the login page with ?error=rate_limited|unavailable"},
    },
)
async def google_login(
    request: Request,
    settings: Annotated[Settings, Depends(get_settings)],
    provider: Annotated[OidcProvider, Depends(get_oidc_provider)],
    states: Annotated[LoginStateStore, Depends(get_login_state_store)],
    limiter: Annotated[RateLimiter, Depends(get_rate_limiter)],
    events: Annotated[SecurityEvents, Depends(get_security_events)],
    next_path: Annotated[str | None, Query(alias="next")] = None,
) -> RedirectResponse:
    client_ip = request.client.host if request.client else None
    try:
        start = await start_google_login(next_path, client_ip, provider, states, limiter, events)
    except GoogleRejectedError as rejection:
        return _to_login_page(rejection.code)
    except DependencyUnavailableError as exc:
        logger.error("auth.google_login_unavailable", exc_info=exc)
        return _to_login_page("unavailable")
    response = RedirectResponse(start.authorization_url, status_code=status.HTTP_302_FOUND)
    response.headers["Cache-Control"] = "no-store"
    response.set_cookie(
        key=BINDING_COOKIE,
        value=start.browser_binding,
        max_age=int(LOGIN_STATE_TTL.total_seconds()),
        path=BINDING_COOKIE_PATH,
        secure=settings.session.cookie_secure,
        httponly=True,
        samesite="lax",
    )
    return response


@router.get(
    GOOGLE_CALLBACK_PATH,
    status_code=status.HTTP_303_SEE_OTHER,
    response_class=RedirectResponse,
    summary="Finish signing in with Google",
    responses={
        303: {
            "description": (
                "Redirect to the saved next path with the session cookie, or to the login "
                "page with ?error=state|provider|nonce|email_unverified|email_conflict|"
                "rate_limited|unavailable|cancelled"
            )
        },
    },
)
async def google_callback(
    request: Request,
    settings: Annotated[Settings, Depends(get_settings)],
    service: Annotated[GoogleLoginService, Depends(get_google_login_service)],
    code: str | None = None,
    state: str | None = None,
    error: str | None = None,
) -> RedirectResponse:
    if error == "access_denied":
        response = _to_login_page("cancelled")
    elif error is not None or code is None or state is None:
        response = _to_login_page("provider" if error is not None else "state")
    else:
        callback = GoogleCallbackDTO(
            code=code,
            state=state,
            browser_binding=request.cookies.get(BINDING_COOKIE),
            current_token=request.cookies.get(settings.session.cookie_name),
            client_ip=request.client.host if request.client else None,
        )
        try:
            result = await service.complete(callback)
        except GoogleRejectedError as rejection:
            response = _to_login_page(rejection.code)
        except DependencyUnavailableError as exc:
            logger.error("auth.google_callback_unavailable", exc_info=exc)
            response = _to_login_page("unavailable")
        else:
            response = RedirectResponse(result.next, status_code=status.HTTP_303_SEE_OTHER)
            response.headers["Cache-Control"] = "no-store"
            set_session_cookie(response, settings, result.token)
    _drop_binding(response, settings)
    return response


@router.post(
    GOOGLE_NOT_ME_PATH,
    status_code=status.HTTP_204_NO_CONTENT,
    response_class=Response,
    summary="Unlink Google and sign out everywhere, from the Google-linked email",
    responses={
        422: {"description": "Token is invalid, expired or already used (token-invalid)"},
        503: {"description": "Token store or database is unavailable"},
    },
)
async def google_not_me(
    body: GoogleNotMeRequest,
    response: Response,
    tokens: Annotated[OneTimeTokenStore, Depends(get_one_time_token_store)],
    uow: Annotated[UnitOfWork, Depends(get_uow)],
    events: Annotated[SecurityEvents, Depends(get_security_events)],
) -> None:
    response.headers["Cache-Control"] = "no-store"
    await disown_google_login(body.token, tokens, uow, events)
