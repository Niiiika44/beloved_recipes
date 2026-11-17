from dataclasses import replace
from datetime import datetime

from app.core.exceptions import RateLimitedError
from app.modules.identity.domain.exceptions import InvalidSessionError, NicknameTakenError
from app.modules.identity.domain.limits import NICKNAME_CHANGE_LIMIT
from app.modules.identity.domain.nicknames import is_quarantined, normalize_nickname
from app.modules.identity.service.dto import MeDTO, ProfileChangesDTO, UserDTO
from app.modules.identity.service.ports import RateLimiter, UnitOfWork

NICKNAME_CHANGE_PREFIX = "nickname_change:"


async def get_me(user: UserDTO, uow: UnitOfWork) -> MeDTO:
    async with uow:
        membership = await uow.users.get_membership(user.id)
    return MeDTO(user=user, membership=membership)


async def update_me(
    user: UserDTO, changes: ProfileChangesDTO, uow: UnitOfWork, limiter: RateLimiter, now: datetime
) -> MeDTO:
    async with uow:
        membership = await uow.users.get_membership(user.id)
        if changes.nickname is None:
            return MeDTO(user=user, membership=membership)
        new_nickname = normalize_nickname(changes.nickname)
        if new_nickname == user.nickname:
            return MeDTO(user=user, membership=membership)
        me = await uow.users.get_for_update(user.id)
        if me is None:
            raise InvalidSessionError()
        if me.nickname == new_nickname:
            return MeDTO(user=me, membership=membership)
        await uow.nicknames.lock([n for n in (me.nickname, new_nickname) if n is not None])
        owner = await uow.nicknames.get_owner(new_nickname)
        if owner is not None:
            raise NicknameTakenError()
        release = await uow.nicknames.get_release(new_nickname)
        if release is not None and is_quarantined(
            released_by=release.released_by,
            released_at=release.released_at,
            user_id=user.id,
            now=now,
        ):
            raise NicknameTakenError()
        if me.nickname is not None:
            retry_after = await limiter.hit(
                NICKNAME_CHANGE_PREFIX + str(user.id), NICKNAME_CHANGE_LIMIT
            )
            if retry_after is not None:
                raise RateLimitedError("Nickname change rate limit exceeded", retry_after)
        await uow.nicknames.change(user.id, me.nickname, new_nickname)
        await uow.commit()
        return MeDTO(user=replace(me, nickname=new_nickname), membership=membership)
