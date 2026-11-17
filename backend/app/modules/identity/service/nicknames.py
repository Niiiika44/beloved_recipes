from datetime import datetime

from app.core.exceptions import RateLimitedError
from app.modules.identity.domain.exceptions import InvalidNicknameError, NicknameRequiredError
from app.modules.identity.domain.limits import NICKNAME_CHECK_LIMIT
from app.modules.identity.domain.nicknames import is_quarantined, normalize_nickname
from app.modules.identity.service.dto import NicknameAvailabilityDTO, UserDTO
from app.modules.identity.service.ports import RateLimiter, UnitOfWork

NICKNAME_CHECK_PREFIX = "nickname_check:"


async def check_nickname(
    user: UserDTO, raw: str, uow: UnitOfWork, limiter: RateLimiter, now: datetime
) -> NicknameAvailabilityDTO:
    retry_after = await limiter.hit(NICKNAME_CHECK_PREFIX + str(user.id), NICKNAME_CHECK_LIMIT)
    if retry_after is not None:
        raise RateLimitedError("Nickname check rate limit exceeded", retry_after)
    try:
        nickname = normalize_nickname(raw=raw)
    except InvalidNicknameError as exc:
        return NicknameAvailabilityDTO(nickname=None, available=False, reason=exc.reason)
    async with uow:
        owner = await uow.nicknames.get_owner(nickname)
        if owner is not None and owner != user.id:
            return NicknameAvailabilityDTO(nickname=nickname, available=False, reason="taken")
        release = await uow.nicknames.get_release(nickname)
        if release is not None and is_quarantined(
            released_by=release.released_by,
            released_at=release.released_at,
            user_id=user.id,
            now=now,
        ):
            return NicknameAvailabilityDTO(nickname=nickname, available=False, reason="taken")
    return NicknameAvailabilityDTO(nickname=nickname, available=True, reason=None)


def ensure_nickname(user: UserDTO) -> UserDTO:
    if user.nickname is None:
        raise NicknameRequiredError()
    return user
