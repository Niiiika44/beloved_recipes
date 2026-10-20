from typing import Annotated

from fastapi import APIRouter, Depends, Request, Response, status

from app.core.config import Settings, get_settings
from app.modules.identity.routes.cookies import cookie_info
from app.modules.identity.routes.dependencies import get_session_store
from app.modules.identity.service.auth import logout
from app.modules.identity.service.ports import SessionStore

router = APIRouter(
    prefix="/auth",
    tags=["auth"],
)


@router.post(
    "/logout",
    response_model=None,
    summary="Log out the current user",
    responses={503: {"description": "Session store is unavailable"}},
    status_code=status.HTTP_204_NO_CONTENT,
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
