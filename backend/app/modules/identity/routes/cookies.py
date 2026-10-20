from typing import Literal, TypedDict


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
