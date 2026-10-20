from typing import Any


def cookie_info(cookie_name: str, cookie_secure: bool) -> dict[str, Any]:
    return {
        "key": cookie_name,
        "path": "/",
        "secure": cookie_secure,
        "httponly": True,
        "samesite": "lax",
    }
