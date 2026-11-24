from dataclasses import replace
from datetime import UTC, datetime

import pytest
from fakes import (
    FakeBreachChecker,
    FakeEvents,
    FakeHasher,
    FakeLimiter,
    FakeTokens,
    FakeUnitOfWork,
    make_user,
)

from app.core.exceptions import AppError, DependencyUnavailableError, RateLimitedError
from app.modules.identity.domain.emails import email_fingerprint
from app.modules.identity.domain.enums import EmailPurpose, TokenPurpose
from app.modules.identity.domain.exceptions import InvalidTokenError, WeakPasswordError
from app.modules.identity.domain.limits import PASSWORD_RESET_EMAIL_LIMIT, PASSWORD_RESET_IP_LIMIT
from app.modules.identity.service.dto import (
    PasswordResetDTO,
    PasswordResetRequestDTO,
    UserDTO,
)
from app.modules.identity.service.password_reset import (
    PasswordResetService,
    request_password_reset,
)

SECRET = b"reset-secret"
TOKEN = "R" * 43
PASSWORD = "brand new horse battery"
VERIFIED_AT = datetime(2026, 11, 20, tzinfo=UTC)
REQUEST = PasswordResetRequestDTO(email="Anna@Example.org", client_ip="203.0.113.7")
RESET = PasswordResetDTO(token=TOKEN, password=PASSWORD)
IP_KEY = "password_reset_ip:203.0.113.7"
EMAIL_KEY = "password_reset_email:" + email_fingerprint("anna@example.org", SECRET)


def _anna(verified: bool = True, version: int = 3) -> UserDTO:
    return replace(
        make_user("Anna"),
        email="anna@example.org",
        email_verified_at=VERIFIED_AT if verified else None,
        credentials_version=version,
    )


class RequestWorld:
    def __init__(self, *users: UserDTO, retry_after: int | None = None) -> None:
        self.uow = FakeUnitOfWork(users)
        self.limiter = FakeLimiter(self.uow, retry_after=retry_after)
        self.events = FakeEvents()

    async def request(self, request: PasswordResetRequestDTO = REQUEST) -> None:
        await request_password_reset(request, self.uow, self.limiter, self.events, SECRET)


class ResetWorld:
    def __init__(
        self,
        user: UserDTO | None = None,
        token_version: int = 3,
        breached: bool | None = False,
    ) -> None:
        self.user = user
        self.uow = FakeUnitOfWork([user] if user else [])
        self.tokens = FakeTokens(self.uow)
        if user is not None:
            self.tokens.plant(TokenPurpose.PASSWORD_RESET, TOKEN, user.id, token_version)
        self.hasher = FakeHasher(self.uow)
        self.checker = FakeBreachChecker(breached, self.uow)
        self.events = FakeEvents()
        self.service = PasswordResetService(
            uow=self.uow,
            tokens=self.tokens,
            hasher=self.hasher,
            breach_checker=self.checker,
            events=self.events,
        )

    async def reset(self, reset: PasswordResetDTO = RESET) -> None:
        await self.service.reset(reset)

    async def refused(self, reset: PasswordResetDTO = RESET) -> AppError:
        with pytest.raises(AppError) as caught:
            await self.service.reset(reset)
        return caught.value

    def token_is_live(self) -> bool:
        return (TokenPurpose.PASSWORD_RESET, TOKEN) in self.tokens.live

    def stored_version(self) -> int:
        assert self.user is not None
        return self.uow.stored[self.user.id].credentials_version


def test_reset_dto_hides_token_and_password() -> None:
    assert TOKEN not in repr(RESET)
    assert PASSWORD not in repr(RESET)


async def test_request_for_known_email_queues_a_reset_letter() -> None:
    anna = _anna()
    world = RequestWorld(anna)

    await world.request()

    assert world.uow.jobs == [(EmailPurpose.PASSWORD_RESET, anna.id)]
    assert world.uow.commits == 1
    assert world.events.recorded == [("password_reset_requested", str(anna.id))]


async def test_request_for_unknown_email_queues_nothing_and_still_succeeds() -> None:
    world = RequestWorld()

    await world.request()

    assert world.uow.jobs == []
    assert world.uow.commits == 0
    assert world.events.recorded == [("password_reset_requested", "-")]


@pytest.mark.parametrize("verified", [True, False], ids=["verified", "unverified"])
async def test_request_queues_a_letter_whatever_the_account_state(verified: bool) -> None:
    anna = _anna(verified=verified)
    world = RequestWorld(anna)

    await world.request(replace(REQUEST, email="ANNA@EXAMPLE.ORG"))

    assert world.uow.jobs == [(EmailPurpose.PASSWORD_RESET, anna.id)]


async def test_request_limits_are_counted_by_ip_then_by_email_fingerprint() -> None:
    world = RequestWorld(_anna())

    await world.request()

    assert world.limiter.hits == [
        (IP_KEY, PASSWORD_RESET_IP_LIMIT),
        (EMAIL_KEY, PASSWORD_RESET_EMAIL_LIMIT),
    ]
    assert world.uow.calls[:2] == ["hit", "hit"]


def test_reset_request_limits_are_five_per_email_and_twenty_per_ip_an_hour() -> None:
    assert (PASSWORD_RESET_EMAIL_LIMIT.limit, PASSWORD_RESET_EMAIL_LIMIT.window.seconds) == (
        5,
        3600,
    )
    assert (PASSWORD_RESET_IP_LIMIT.limit, PASSWORD_RESET_IP_LIMIT.window.seconds) == (20, 3600)


async def test_request_limit_keys_reveal_no_email() -> None:
    world = RequestWorld(_anna())

    await world.request()

    assert all("anna" not in key.lower() for key, _ in world.limiter.hits)


async def test_request_without_client_address_shares_one_ip_key() -> None:
    world = RequestWorld(_anna())

    await world.request(replace(REQUEST, client_ip=None))

    assert world.limiter.hits[0][0] == "password_reset_ip:unknown"


@pytest.mark.parametrize(
    ("scope", "refusing", "hits"),
    [("ip", "password_reset_ip:", 1), ("email", "password_reset_email:", 2)],
)
async def test_exceeded_request_limit_is_429_before_anything_is_read(
    scope: str, refusing: str, hits: int
) -> None:
    world = RequestWorld(_anna(), retry_after=600)
    world.limiter.refusing = refusing

    with pytest.raises(RateLimitedError) as caught:
        await world.request()

    assert caught.value.retry_after_seconds == 600
    assert world.uow.calls == ["hit"] * hits
    assert world.uow.jobs == []
    assert world.events.recorded == [("rate_limited", "password_reset", scope)]


async def test_reset_sets_the_password_verifies_email_and_bumps_the_version() -> None:
    anna = _anna(verified=False)
    world = ResetWorld(anna)

    await world.reset()

    assert world.uow.password_hashes == {anna.id: "$argon2id$fake$1"}
    assert world.hasher.passwords == [PASSWORD]
    assert world.uow.verified == [anna.id]
    assert world.stored_version() == 4
    assert world.uow.commits == 1
    assert world.events.recorded == [("password_reset_completed", str(anna.id))]


async def test_reset_follows_the_safe_order() -> None:
    world = ResetWorld(_anna())

    await world.reset()

    assert world.uow.calls == [
        "peek",
        "is_breached",
        "hash",
        "get_for_update",
        "set_hash",
        "mark_email_verified",
        "bump_credentials_version",
        "commit",
        "consume",
    ]
    assert not any(world.hasher.inside_uow)


async def test_reset_hashes_the_normalized_password() -> None:
    world = ResetWorld(_anna())

    await world.reset(replace(RESET, password="ｂｒａｎｄ new horse battery"))

    assert world.hasher.passwords == [PASSWORD]
    assert world.checker.passwords == [PASSWORD]


@pytest.mark.parametrize("password", ["short", "        ", "x" * 129, "brand new \ud800 horse"])
async def test_password_of_invalid_format_is_refused_before_the_token_is_read(
    password: str,
) -> None:
    world = ResetWorld(_anna())

    refusal = await world.refused(replace(RESET, password=password))

    assert isinstance(refusal, WeakPasswordError)
    assert world.uow.calls == []
    assert world.token_is_live()


async def test_breached_password_is_refused_and_the_link_keeps_working() -> None:
    anna = _anna()
    world = ResetWorld(anna, breached=True)

    refusal = await world.refused()

    assert isinstance(refusal, WeakPasswordError)
    assert refusal.reason == "breached"
    assert world.token_is_live()
    assert world.uow.password_hashes == {}
    assert world.stored_version() == 3

    world.checker.answer = False
    await world.reset()

    assert world.uow.password_hashes == {anna.id: "$argon2id$fake$1"}


async def test_unavailable_breach_check_lets_the_reset_through() -> None:
    world = ResetWorld(_anna(), breached=None)

    await world.reset()

    assert ("breach_check_unavailable",) in world.events.recorded
    assert world.uow.commits == 1


@pytest.mark.parametrize("token", ["A" * 43, "short"], ids=["unknown", "malformed"])
async def test_unknown_token_is_refused_without_breach_check_or_hashing(token: str) -> None:
    world = ResetWorld(_anna())

    refusal = await world.refused(replace(RESET, token=token))

    assert isinstance(refusal, InvalidTokenError)
    assert world.checker.passwords == []
    assert world.hasher.passwords == []
    assert world.uow.calls == ["peek"]


async def test_token_of_another_purpose_is_refused() -> None:
    anna = _anna()
    world = ResetWorld(anna)
    world.tokens.live.clear()
    world.tokens.plant(TokenPurpose.EMAIL_CONFIRM, TOKEN, anna.id, 3)

    refusal = await world.refused()

    assert isinstance(refusal, InvalidTokenError)
    assert world.uow.password_hashes == {}


@pytest.mark.parametrize("token_version", [2, 4])
async def test_token_issued_for_another_credentials_version_is_refused(
    token_version: int,
) -> None:
    world = ResetWorld(_anna(version=3), token_version=token_version)

    refusal = await world.refused()

    assert isinstance(refusal, InvalidTokenError)
    assert world.uow.password_hashes == {}
    assert world.uow.verified == []
    assert world.uow.commits == 0
    assert world.stored_version() == 3


async def test_token_of_a_deleted_user_is_refused() -> None:
    anna = _anna()
    world = ResetWorld(anna)
    del world.uow.stored[anna.id]

    refusal = await world.refused()

    assert isinstance(refusal, InvalidTokenError)
    assert world.uow.commits == 0


async def test_the_same_link_does_not_work_twice() -> None:
    world = ResetWorld(_anna())
    await world.reset()

    refusal = await world.refused()

    assert isinstance(refusal, InvalidTokenError)
    assert world.stored_version() == 4


async def test_failed_cleanup_after_commit_is_an_event_not_an_error() -> None:
    anna = _anna()
    world = ResetWorld(anna)
    world.tokens.consume_failure = DependencyUnavailableError("Token store is unavailable")

    await world.reset()

    assert world.uow.commits == 1
    assert world.events.recorded == [
        ("password_reset_completed", str(anna.id)),
        ("reset_token_cleanup_failed",),
    ]


async def test_link_left_behind_by_a_failed_cleanup_is_dead() -> None:
    world = ResetWorld(_anna())
    world.tokens.consume_failure = DependencyUnavailableError("Token store is unavailable")
    await world.reset()
    world.tokens.consume_failure = None

    refusal = await world.refused()

    assert world.token_is_live()
    assert isinstance(refusal, InvalidTokenError)


async def test_token_store_outage_before_the_reset_is_reported() -> None:
    world = ResetWorld(_anna())
    outage = DependencyUnavailableError("Token store is unavailable")
    world.tokens.peek_failure = outage

    refusal = await world.refused()

    assert refusal is outage
    assert world.checker.passwords == []
    assert world.uow.password_hashes == {}


async def test_reset_events_carry_neither_token_nor_password() -> None:
    world = ResetWorld(_anna(), breached=None)
    world.tokens.consume_failure = DependencyUnavailableError("Token store is unavailable")

    await world.reset()

    everything = repr(world.events.recorded)
    assert TOKEN not in everything
    assert "horse" not in everything
