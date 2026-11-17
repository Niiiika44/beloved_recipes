import uuid
from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest
from fakes import FakeLimiter, FakeUnitOfWork, make_user

from app.core.exceptions import DependencyUnavailableError, RateLimitedError
from app.modules.identity.domain.exceptions import NicknameRequiredError
from app.modules.identity.domain.limits import NICKNAME_CHECK_LIMIT
from app.modules.identity.service.dto import NicknameAvailabilityDTO, ReleasedNicknameDTO, UserDTO
from app.modules.identity.service.nicknames import check_nickname, ensure_nickname

NOW = datetime(2030, 3, 1, 12, 0, tzinfo=UTC)
FREE = NicknameAvailabilityDTO(nickname="boris", available=True, reason=None)
TAKEN = NicknameAvailabilityDTO(nickname="boris", available=False, reason="taken")


def _world(
    *users: UserDTO,
    releases: dict[str, ReleasedNicknameDTO] | None = None,
    retry_after: int | None = None,
    failure: Exception | None = None,
) -> tuple[FakeUnitOfWork, FakeLimiter]:
    uow = FakeUnitOfWork(users, releases=releases)
    return uow, FakeLimiter(uow, retry_after=retry_after, failure=failure)


def _released(by: uuid.UUID | None, ago: timedelta) -> ReleasedNicknameDTO:
    return ReleasedNicknameDTO(released_by=by, released_at=NOW - ago)


async def test_free_nickname_is_available_in_normalized_form() -> None:
    user = make_user(nickname="anna")
    uow, limiter = _world(user)

    assert await check_nickname(user, " Boris ", uow, limiter, NOW) == FREE


async def test_nickname_of_another_user_is_taken() -> None:
    user = make_user(nickname="anna")
    uow, limiter = _world(user, make_user("Owner", nickname="boris"))

    assert await check_nickname(user, "BORIS", uow, limiter, NOW) == TAKEN


async def test_own_current_nickname_is_available() -> None:
    user = make_user(nickname="boris")
    uow, limiter = _world(user)

    assert await check_nickname(user, "boris", uow, limiter, NOW) == FREE


@pytest.mark.parametrize(
    "ago", [timedelta(0), timedelta(days=29, hours=23)], ids=["just_now", "almost_month"]
)
async def test_nickname_in_someone_elses_quarantine_is_taken(ago: timedelta) -> None:
    user = make_user()
    uow, limiter = _world(user, releases={"boris": _released(uuid.uuid7(), ago)})

    assert await check_nickname(user, "boris", uow, limiter, NOW) == TAKEN


async def test_nickname_of_deleted_account_in_quarantine_is_taken() -> None:
    user = make_user()
    uow, limiter = _world(user, releases={"boris": _released(None, timedelta(days=1))})

    assert await check_nickname(user, "boris", uow, limiter, NOW) == TAKEN


async def test_own_quarantined_nickname_is_available() -> None:
    user = make_user(nickname="anna")
    uow, limiter = _world(user, releases={"boris": _released(user.id, timedelta(hours=1))})

    assert await check_nickname(user, "boris", uow, limiter, NOW) == FREE


async def test_quarantine_is_judged_by_the_given_moment() -> None:
    user = make_user()
    uow, limiter = _world(user, releases={"boris": _released(uuid.uuid7(), timedelta(days=31))})

    assert await check_nickname(user, "boris", uow, limiter, NOW) == FREE


@pytest.mark.parametrize(
    ("raw", "reason"),
    [
        ("", "too_short"),
        ("ab", "too_short"),
        ("a" * 31, "too_long"),
        ("anna b", "bad_characters"),
        ("anna..b", "bad_dots"),
        ("Admin", "reserved"),
    ],
)
async def test_invalid_nickname_is_a_verdict_not_an_error(raw: str, reason: str) -> None:
    user = make_user()
    uow, limiter = _world(user)

    found = await check_nickname(user, raw, uow, limiter, NOW)

    assert found == NicknameAvailabilityDTO(nickname=None, available=False, reason=reason)
    assert uow.calls == ["hit"]


async def test_check_works_for_user_without_nickname() -> None:
    user = make_user()
    uow, limiter = _world(user)

    assert await check_nickname(user, "boris", uow, limiter, NOW) == FREE


async def test_check_only_reads() -> None:
    user = make_user(nickname="anna")
    uow, limiter = _world(user, releases={"boris": _released(uuid.uuid7(), timedelta(days=40))})

    await check_nickname(user, "boris", uow, limiter, NOW)

    assert uow.calls == ["hit", "get_owner", "get_release"]
    assert uow.commits == 0
    assert uow.active is False


async def test_every_check_spends_the_users_own_limit() -> None:
    user = make_user()
    uow, limiter = _world(user)

    await check_nickname(user, "boris", uow, limiter, NOW)
    await check_nickname(user, "a b", uow, limiter, NOW)

    assert limiter.hits == [(f"nickname_check:{user.id}", NICKNAME_CHECK_LIMIT)] * 2


async def test_exceeded_limit_is_reported_before_reading_anything() -> None:
    user = make_user()
    uow, limiter = _world(user, retry_after=42)

    with pytest.raises(RateLimitedError) as caught:
        await check_nickname(user, "boris", uow, limiter, NOW)

    assert caught.value.retry_after_seconds == 42
    assert uow.calls == ["hit"]


async def test_limiter_outage_is_reported() -> None:
    user = make_user()
    outage = DependencyUnavailableError("Rate limiter is unavailable")
    uow, limiter = _world(user, failure=outage)

    with pytest.raises(DependencyUnavailableError) as caught:
        await check_nickname(user, "boris", uow, limiter, NOW)

    assert caught.value is outage


def test_user_with_nickname_passes_the_gate() -> None:
    user = make_user(nickname="anna")

    assert ensure_nickname(user) is user


def test_user_without_nickname_is_stopped_at_the_gate() -> None:
    with pytest.raises(NicknameRequiredError):
        ensure_nickname(replace(make_user(), nickname=None))
