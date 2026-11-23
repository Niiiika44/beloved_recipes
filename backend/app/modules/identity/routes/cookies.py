from typing import Literal, TypedDict

from fastapi import Response

from app.core.config import Settings


class CookieParams(TypedDict):
    key: str
    path: str | None
    secure: bool
    httponly: bool
    samesite: Literal["lax", "strict", "none"] | None


def cookie_info(cookie_name: str, cookie_secure: bool) -> CookieParams:
    return {
        "key": cookie_name,
        "path": "/",
        "secure": cookie_secure,
        "httponly": True,
        "samesite": "lax",
    }


def set_session_cookie(response: Response, settings: Settings, token: str) -> None:
    cookie = cookie_info(settings.session.cookie_name, settings.session.cookie_secure)
    response.set_cookie(**cookie, value=token, max_age=settings.session.absolute_ttl_seconds)
