from app.modules.identity.domain.exceptions import InvalidSessionError
from app.modules.identity.service.dto import UserDTO
from app.modules.identity.service.ports import SecurityEvents, SessionStore, UnitOfWork


async def authenticate(token: str | None, store: SessionStore, uow: UnitOfWork) -> UserDTO:
    if not token:
        raise InvalidSessionError
    session = await store.resolve(token)
    if session is None:
        raise InvalidSessionError
    async with uow:
        user = await uow.users.get(session.user_id)
    if user is None or session.credentials_version != user.credentials_version:
        await store.revoke(token)
        raise InvalidSessionError
    return user


async def logout(token: str | None, store: SessionStore, events: SecurityEvents) -> None:
    if not token:
        return
    session = await store.resolve(token=token)
    await store.revoke(token)
    if session is None:
        events.logout(user_id=None)
    else:
        events.logout(user_id=session.user_id)
