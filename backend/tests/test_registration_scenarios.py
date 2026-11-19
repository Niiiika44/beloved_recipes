from dataclasses import replace

import pytest
from fakes import (
    FakeBreachChecker,
    FakeEvents,
    FakeHasher,
    FakeLimiter,
    FakeUnitOfWork,
    FakeUsers,
    make_user,
)

from app.core.exceptions import DependencyUnavailableError, RateLimitedError
from app.modules.identity.domain.enums import EmailPurpose
from app.modules.identity.domain.exceptions import InvalidDisplayNameError, WeakPasswordError
from app.modules.identity.domain.limits import (
    REGISTRATION_EMAIL_LIMIT,
    REGISTRATION_IP_LIMIT,
    RateLimit,
    email_fingerprint,
)
from app.modules.identity.service.dto import RegistrationDTO, UserDTO
from app.modules.identity.service.registration import RegistrationService

SECRET = b"registration-secret"
REGISTRATION = RegistrationDTO(
    email="Anna@Example.org",
    password="correct horse battery",
    display_name="  Anna  ",
    client_ip="203.0.113.7",
)
IP_KEY = "registration_ip:203.0.113.7"
EMAIL_KEY = "registration_email:" + email_fingerprint("anna@example.org", SECRET)


class World:
    def __init__(
        self,
        *users: UserDTO,
        breached: bool | None = False,
        retry_after: int | None = None,
        failure: Exception | None = None,
    ) -> None:
        self.uow = FakeUnitOfWork(users)
        self.limiter = FakeLimiter(self.uow, retry_after=retry_after, failure=failure)
        self.hasher = FakeHasher(self.uow)
        self.checker = FakeBreachChecker(breached, self.uow)
        self.events = FakeEvents()
        self.service = RegistrationService(
            uow=self.uow,
            limiter=self.limiter,
            hasher=self.hasher,
            breach_checker=self.checker,
            events=self.events,
            secret=SECRET,
        )

    async def register(self, registration: RegistrationDTO = REGISTRATION) -> None:
        await self.service.register(registration)


def _taken(email: str = "anna@example.org") -> UserDTO:
    return replace(make_user("Anna"), email=email)


def test_registration_dto_hides_the_password() -> None:
    assert "correct horse battery" not in repr(REGISTRATION)
    assert "Anna@Example.org" in repr(REGISTRATION)


async def test_new_email_creates_user_with_password_and_confirmation() -> None:
    world = World()

    await world.register()

    [user] = world.uow.created
    assert user.email == "Anna@Example.org"
    assert user.display_name == "Anna"
    assert world.uow.password_hashes == {user.id: "$argon2id$fake$1"}
    assert world.uow.jobs == [(EmailPurpose.EMAIL_CONFIRM, user.id)]
    assert world.uow.commits == 1
    assert world.uow.active is False


async def test_new_email_follows_the_safe_order() -> None:
    world = World()

    await world.register()

    assert world.uow.calls == [
        "hit",
        "hit",
        "is_breached",
        "hash",
        "create",
        "set_hash",
        "enqueue",
        "commit",
    ]


async def test_limits_are_counted_by_ip_then_by_email_fingerprint() -> None:
    world = World()

    await world.register()

    assert world.limiter.hits == [
        (IP_KEY, REGISTRATION_IP_LIMIT),
        (EMAIL_KEY, REGISTRATION_EMAIL_LIMIT),
    ]


@pytest.mark.parametrize("email", ["anna@example.org", "ANNA@EXAMPLE.ORG"])
async def test_email_limit_key_ignores_case(email: str) -> None:
    world = World()

    await world.register(replace(REGISTRATION, email=email))

    assert world.limiter.hits[1][0] == EMAIL_KEY


async def test_email_limit_key_reveals_no_email() -> None:
    world = World()

    await world.register()

    assert all("anna" not in key.lower() for key, _ in world.limiter.hits)


async def test_email_limit_key_is_keyed_by_the_secret() -> None:
    world = World()
    world.service = RegistrationService(
        uow=world.uow,
        limiter=world.limiter,
        hasher=world.hasher,
        breach_checker=world.checker,
        events=world.events,
        secret=b"another-secret",
    )

    await world.register()

    assert world.limiter.hits[1][0] != EMAIL_KEY


async def test_unknown_client_shares_one_ip_counter() -> None:
    world = World()

    await world.register(replace(REGISTRATION, client_ip=None))

    assert world.limiter.hits[0][0] == "registration_ip:unknown"


@pytest.mark.parametrize(
    ("password", "reason"),
    [("short", "too_short"), ("        ", "blank"), ("x" * 129, "too_long")],
)
async def test_weak_password_is_rejected_before_spending_anything(
    password: str, reason: str
) -> None:
    world = World()

    with pytest.raises(WeakPasswordError) as caught:
        await world.register(replace(REGISTRATION, password=password))

    assert caught.value.reason == reason
    assert world.uow.calls == []
    assert world.limiter.hits == []


async def test_invalid_display_name_is_rejected_before_spending_anything() -> None:
    world = World()

    with pytest.raises(InvalidDisplayNameError):
        await world.register(replace(REGISTRATION, display_name="   "))

    assert world.uow.calls == []


async def test_ip_over_the_limit_stops_before_the_email_counter() -> None:
    world = World(retry_after=1800)

    with pytest.raises(RateLimitedError) as caught:
        await world.register()

    assert caught.value.retry_after_seconds == 1800
    assert world.limiter.hits == [(IP_KEY, REGISTRATION_IP_LIMIT)]
    assert world.events.recorded == [("rate_limited", "registration", "ip")]
    assert world.uow.calls == ["hit"]


async def test_email_over_the_limit_is_reported_as_email() -> None:
    world = World()

    class EmailLimited(FakeLimiter):
        async def hit(self, key: str, rule: RateLimit) -> int | None:
            await super().hit(key, rule)
            return 600 if key == EMAIL_KEY else None

    world.service = RegistrationService(
        uow=world.uow,
        limiter=EmailLimited(world.uow),
        hasher=world.hasher,
        breach_checker=world.checker,
        events=world.events,
        secret=SECRET,
    )

    with pytest.raises(RateLimitedError) as caught:
        await world.register()

    assert caught.value.retry_after_seconds == 600
    assert world.events.recorded == [("rate_limited", "registration", "email")]
    assert world.uow.calls == ["hit", "hit"]


async def test_limiter_outage_is_reported_and_nothing_is_saved() -> None:
    outage = DependencyUnavailableError("Rate limiter is unavailable")
    world = World(failure=outage)

    with pytest.raises(DependencyUnavailableError) as caught:
        await world.register()

    assert caught.value is outage
    assert world.uow.created == []


async def test_breached_password_is_rejected_before_hashing() -> None:
    world = World(breached=True)

    with pytest.raises(WeakPasswordError) as caught:
        await world.register()

    assert caught.value.reason == "breached"
    assert world.hasher.passwords == []
    assert world.uow.created == []
    assert world.events.recorded == []


async def test_unknown_breach_status_lets_registration_through_with_event() -> None:
    world = World(breached=None)

    await world.register()

    assert world.events.recorded == [("breach_check_unavailable",)]
    assert len(world.uow.created) == 1


async def test_password_is_normalized_before_checking_and_hashing() -> None:
    world = World()

    await world.register(replace(REGISTRATION, password="ｃｏｒｒｅｃｔ horse battery"))

    assert world.checker.passwords == ["correct horse battery"]
    assert world.hasher.passwords == ["correct horse battery"]


@pytest.mark.parametrize("taken", ["anna@example.org", "ANNA@EXAMPLE.ORG"])
async def test_taken_email_gets_already_registered_and_keeps_its_password(taken: str) -> None:
    existing = _taken(taken)
    world = World(existing)

    await world.register()

    assert world.uow.created == []
    assert world.uow.password_hashes == {}
    assert world.uow.jobs == [(EmailPurpose.ALREADY_REGISTERED, existing.id)]
    assert world.uow.commits == 1


async def test_taken_email_never_gets_a_new_confirmation() -> None:
    world = World(_taken())

    await world.register()

    assert all(purpose != EmailPurpose.EMAIL_CONFIRM for purpose, _ in world.uow.jobs)


async def test_taken_email_is_hashed_like_a_free_one() -> None:
    world = World(_taken())

    await world.register()

    assert world.uow.calls == [
        "hit",
        "hit",
        "is_breached",
        "hash",
        "create",
        "find_by_email",
        "enqueue",
        "commit",
    ]


async def test_account_deleted_meanwhile_gets_no_letter() -> None:
    world = World(_taken())

    class VanishingUsers(FakeUsers):
        async def find_by_email(self, email: str) -> UserDTO | None:
            await super().find_by_email(email)
            return None

    world.uow.users = VanishingUsers(world.uow)

    await world.register()

    assert world.uow.jobs == []
    assert world.uow.password_hashes == {}
    assert world.uow.commits == 1


async def test_service_keeps_no_request_data_between_calls() -> None:
    world = World()

    await world.register()
    await world.register(replace(REGISTRATION, email="boris@example.org"))

    assert [user.email for user in world.uow.created] == ["Anna@Example.org", "boris@example.org"]
    assert set(vars(world.service)) == {
        "_uow",
        "_limiter",
        "_hasher",
        "_breach_checker",
        "_events",
        "_secret",
    }
