import re
import unicodedata
from datetime import timedelta

from app.modules.identity.domain.exceptions import InvalidNicknameError

NICKNAME_MIN_LENGTH = 3
NICKNAME_MAX_LENGTH = 30
NICKNAME_QUARANTINE = timedelta(days=30)
RESERVED_NICKNAMES = frozenset(
    {
        "admin",
        "administrator",
        "api",
        "auth",
        "help",
        "me",
        "moderator",
        "null",
        "root",
        "settings",
        "support",
        "system",
        "undefined",
        "www",
    }
)

_ALLOWED = re.compile(r"[a-z0-9_.]+")


def normalize_nickname(raw: str) -> str:
    nickname = unicodedata.normalize("NFKC", raw).strip().lower()
    if len(nickname) < NICKNAME_MIN_LENGTH:
        raise InvalidNicknameError("too_short")
    if len(nickname) > NICKNAME_MAX_LENGTH:
        raise InvalidNicknameError("too_long")
    if not _ALLOWED.fullmatch(nickname):
        raise InvalidNicknameError("bad_characters")
    if nickname.startswith(".") or nickname.endswith(".") or ".." in nickname:
        raise InvalidNicknameError("bad_dots")
    if nickname in RESERVED_NICKNAMES:
        raise InvalidNicknameError("reserved")
    return nickname
