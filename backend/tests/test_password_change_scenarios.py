from dataclasses import replace
from datetime import timedelta

import pytest
from fakes import (
    FakeBreachChecker,
    FakeEvents,
    FakeHasher,
    FakeLimiter,
    FakeSessions,
    FakeUnitOfWork,
    make_user,
)

from app.core.exceptions import AppError, DependencyUnavailableError, RateLimitedError
from app.modules.identity.domain.exceptions import (
    InvalidCredentialsError,
    InvalidSessionError,
    PasswordNotSetError,
    WeakPasswordError,
)
from app.modules.identity.domain.limits import PASSWORD_CHANGE_LIMIT
from app.modules.identity.service.dto import PasswordChangeDTO, UserDTO
from app.modules.identity.service.password_change import PasswordChangeService

CURRENT = "correct horse battery"
NEW = "brand new horse battery"
STORED_HASH = "$argon2id$stored"
CURRENT_TOKEN = "C" * 43
CHANGE = PasswordChangeDTO(current=CURRENT, new=NEW)


def _anna(version: int = 3) -> UserDTO:
    return replace(make_user("Anna"), email="anna@example.org", credentials_version=version)


class World:
    def __init__(
        self,
        user: UserDTO | None = None,
        password_hash: str | None = STORED_HASH,
        retry_after: int | None = None,
        breached: bool | None = False,
    ) -> None:
        self.user = user or _anna()
        self.uow = FakeUnitOfWork([self.user])
        if password_hash is not None:
            self.uow.password_hashes[self.user.id] = password_hash
        self.limiter = FakeLimiter(self.uow, retry_after=retry_after)
        self.hasher = FakeHasher(self.uow, accepted={STORED_HASH: CURRENT})
        self.checker = FakeBreachChecker(breached, self.uow)
        self.sessions = FakeSessions(self.uow, live={CURRENT_TOKEN: self.user.id})
        self.events = FakeEvents()
        self.service = PasswordChangeService(
            uow=self.uow,
            limiter=self.limiter,
            hasher=self.hasher,
            breach_checker=self.checker,
            sessions=self.sessions,
            events=self.events,
        )

    async def change(self, change: PasswordChangeDTO = CHANGE) -> str:
        return await self.service.change(self.user, change)

    async def refused(self, change: PasswordChangeDTO = CHANGE) -> AppError:
        with pytest.raises(AppError) as caught:
            await self.service.change(self.user, change)
        return caught.value

    def stored_version(self) -> int:
        return self.uow.stored[self.user.id].credentials_version


def test_change_dto_hides_passwords() -> None:
    assert CURRENT not in repr(CHANGE)
    assert NEW not in repr(CHANGE)


async def test_change_stores_the_new_password_and_bumps_the_version() -> None:
    world = World()

    await world.change()

    assert world.uow.password_hashes == {world.user.id: "$argon2id$fake$1"}
    assert world.hasher.passwords == [NEW]
    assert world.stored_version() == 4
    assert world.uow.commits == 1
    assert world.events.recorded == [("password_changed", str(world.user.id))]


async def test_this_device_gets_a_new_session_of_the_new_version() -> None:
    world = World()

    token = await world.change()

    assert world.sessions.created == [(world.user.id, token)]
    assert world.sessions.versions[token] == 4
    assert token != CURRENT_TOKEN
    assert world.sessions.revoked == []


async def test_new_session_version_comes_from_the_database_not_the_caller() -> None:
    world = World(_anna(version=7))
    world.user = replace(world.user, credentials_version=1)

    token = await world.change()

    assert world.sessions.versions[token] == 8


async def test_failure_to_open_the_new_session_is_reported_after_the_change() -> None:
    world = World()
    outage = DependencyUnavailableError("Session store is unavailable")
    world.sessions.failure = outage

    refusal = await world.refused()

    assert refusal is outage
    assert world.uow.commits == 1
    assert world.stored_version() == 4


async def test_change_follows_the_safe_order() -> None:
    world = World()

    await world.change()

    assert world.uow.calls == [
        "hit",
        "get_hash",
        "verify",
        "is_breached",
        "hash",
        "get_for_update",
        "set_hash",
        "bump_credentials_version",
        "commit",
        "create_session",
    ]
    assert not any(world.hasher.inside_uow)
    assert not any(world.sessions.inside_uow)


async def test_current_password_is_checked_in_normalized_form() -> None:
    world = World()

    await world.change(replace(CHANGE, current="ｃｏｒｒｅｃｔ horse battery"))

    assert world.hasher.verified == [(STORED_HASH, CURRENT)]
    assert world.uow.commits == 1


async def test_new_password_is_stored_in_normalized_form() -> None:
    world = World()

    await world.change(replace(CHANGE, new="ｂｒａｎｄ new horse battery"))

    assert world.hasher.passwords == [NEW]


@pytest.mark.parametrize("current", ["short", "        ", "x" * 129, "correct \ud800 horse"])
async def test_current_password_of_invalid_format_is_401_without_spending_the_limit(
    current: str,
) -> None:
    world = World()

    refusal = await world.refused(replace(CHANGE, current=current))

    assert isinstance(refusal, InvalidCredentialsError)
    assert world.limiter.hits == []
    assert world.uow.calls == []


@pytest.mark.parametrize("new", ["short", "        ", "x" * 129, "brand \ud800 horse battery"])
async def test_new_password_of_invalid_format_is_422_without_spending_the_limit(
    new: str,
) -> None:
    world = World()

    refusal = await world.refused(replace(CHANGE, new=new))

    assert isinstance(refusal, WeakPasswordError)
    assert world.limiter.hits == []
    assert world.uow.calls == []


async def test_attempts_are_counted_per_user() -> None:
    world = World()

    await world.change()

    assert world.limiter.hits == [(f"password_change:{world.user.id}", PASSWORD_CHANGE_LIMIT)]


def test_change_limit_is_five_an_hour() -> None:
    assert PASSWORD_CHANGE_LIMIT.limit == 5
    assert PASSWORD_CHANGE_LIMIT.window == timedelta(hours=1)


async def test_exceeded_limit_is_429_before_anything_is_read() -> None:
    world = World(retry_after=900)

    refusal = await world.refused()

    assert isinstance(refusal, RateLimitedError)
    assert refusal.retry_after_seconds == 900
    assert world.uow.calls == ["hit"]
    assert world.events.recorded == [("rate_limited", "password_change", "user")]


async def test_wrong_current_password_is_401_and_spends_an_attempt() -> None:
    world = World()

    refusal = await world.refused(replace(CHANGE, current="wrong horse battery"))

    assert isinstance(refusal, InvalidCredentialsError)
    assert len(world.limiter.hits) == 1
    assert world.checker.passwords == []
    assert world.uow.password_hashes == {world.user.id: STORED_HASH}
    assert world.stored_version() == 3
    assert world.sessions.revoked == []
    assert world.sessions.created == []


async def test_account_without_password_is_409() -> None:
    world = World(password_hash=None)

    refusal = await world.refused()

    assert isinstance(refusal, PasswordNotSetError)
    assert world.hasher.verified == []
    assert world.uow.commits == 0


async def test_breached_new_password_is_422_and_nothing_changes() -> None:
    world = World(breached=True)

    refusal = await world.refused()

    assert isinstance(refusal, WeakPasswordError)
    assert refusal.reason == "breached"
    assert world.uow.password_hashes == {world.user.id: STORED_HASH}
    assert world.stored_version() == 3
    assert world.sessions.created == []


async def test_unavailable_breach_check_lets_the_change_through() -> None:
    world = World(breached=None)

    await world.change()

    assert ("breach_check_unavailable",) in world.events.recorded
    assert world.uow.commits == 1


async def test_user_deleted_during_the_change_is_401_and_nothing_is_written() -> None:
    world = World()
    del world.uow.stored[world.user.id]

    refusal = await world.refused()

    assert isinstance(refusal, InvalidSessionError)
    assert world.uow.commits == 0
    assert world.sessions.created == []


async def test_change_events_carry_no_passwords_or_tokens() -> None:
    world = World(breached=None)

    token = await world.change()

    everything = repr(world.events.recorded)
    assert "horse" not in everything
    assert token not in everything
