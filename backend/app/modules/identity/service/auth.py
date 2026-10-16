from app.modules.identity.domain.exceptions import InvalidSessionError
from app.modules.identity.service.dto import MeDTO, UserDTO
from app.modules.identity.service.ports import SessionStore, UnitOfWork


async def authenticate(token: str | None, store: SessionStore, uow: UnitOfWork) -> UserDTO:
    if not token:
        raise InvalidSessionError
    session = await store.resolve(token)
    if session is None:
        raise InvalidSessionError
    async with uow:
        user = await uow.users.get(session.user_id)
    if user is None:
        await store.revoke(token)
        raise InvalidSessionError
    return user


async def logout(token: str | None, store: SessionStore) -> None:
    if not token:
        return None
    await store.revoke(token)


async def get_me(user: UserDTO, uow: UnitOfWork) -> MeDTO:
    async with uow:
        membership = await uow.users.get_membership(user.id)
    return MeDTO(user=user, membership=membership)
