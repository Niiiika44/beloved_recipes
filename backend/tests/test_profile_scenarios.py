import uuid
from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest
from fakes import FakeLimiter, FakeUnitOfWork, make_user

from app.core.exceptions import DependencyUnavailableError, NotAuthenticatedError, RateLimitedError
from app.modules.identity.domain.enums import WorkspaceRole
from app.modules.identity.domain.exceptions import InvalidNicknameError, NicknameTakenError
from app.modules.identity.domain.limits import NICKNAME_CHANGE_LIMIT
from app.modules.identity.service.dto import (
    MembershipDTO,
    ProfileChangesDTO,
    ReleasedNicknameDTO,
    UserDTO,
)
from app.modules.identity.service.ports import RateLimiter
from app.modules.identity.service.profile import get_me, update_me

NOW = datetime(2030, 3, 1, 12, 0, tzinfo=UTC)
MEMBERSHIP = MembershipDTO(
    workspace_id=uuid.UUID("01900000-0000-7000-8000-0000000000aa"),
    workspace_name="Home",
    role=WorkspaceRole.OWNER,
)


def _world(
    *users: UserDTO,
    releases: dict[str, ReleasedNicknameDTO] | None = None,
    retry_after: int | None = None,
    failure: Exception | None = None,
) -> tuple[FakeUnitOfWork, FakeLimiter]:
    uow = FakeUnitOfWork(users, {user.id: MEMBERSHIP for user in users}, releases)
    return uow, FakeLimiter(uow, retry_after=retry_after, failure=failure)


async def _update(
    user: UserDTO, nickname: str | None, uow: FakeUnitOfWork, limiter: FakeLimiter
) -> UserDTO:
    me = await update_me(user, ProfileChangesDTO(nickname=nickname), uow, limiter, NOW)
    assert me.membership == MEMBERSHIP
    return me.user


def _released(by: uuid.UUID | None, ago: timedelta) -> ReleasedNicknameDTO:
    return ReleasedNicknameDTO(released_by=by, released_at=NOW - ago)


def test_fake_limiter_satisfies_the_port() -> None:
    limiter: RateLimiter = FakeLimiter()

    assert limiter is not None


async def test_me_without_workspace_has_no_membership() -> None:
    user = make_user()
    uow = FakeUnitOfWork([user])

    me = await get_me(user, uow)

    assert me.user == user
    assert me.membership is None


@pytest.mark.parametrize("role", list(WorkspaceRole))
async def test_me_includes_membership(role: WorkspaceRole) -> None:
    user = make_user()
    membership = MembershipDTO(workspace_id=uuid.uuid7(), workspace_name="Home", role=role)
    uow = FakeUnitOfWork([user], {user.id: membership})

    me = await get_me(user, uow)

    assert me.user == user
    assert me.membership == membership


async def test_me_does_not_commit() -> None:
    user = make_user()
    uow = FakeUnitOfWork([user])

    await get_me(user, uow)

    assert uow.commits == 0
    assert uow.active is False


async def test_empty_changes_return_profile_untouched() -> None:
    user = make_user(nickname="anna")
    uow, limiter = _world(user)

    found = await _update(user, None, uow, limiter)

    assert found == user
    assert uow.calls == ["get_membership"]
    assert limiter.hits == []


async def test_first_nickname_is_set() -> None:
    user = make_user()
    uow, limiter = _world(user)

    found = await _update(user, "  Anna ", uow, limiter)

    assert found == replace(user, nickname="anna")
    assert uow.changes == [(user.id, None, "anna")]
    assert uow.commits == 1
    assert uow.active is False


async def test_first_nickname_locks_only_itself_and_spends_no_limit() -> None:
    user = make_user()
    uow, limiter = _world(user)

    await _update(user, "anna", uow, limiter)

    assert uow.locked == [["anna"]]
    assert limiter.hits == []


async def test_first_nickname_follows_the_safe_order() -> None:
    user = make_user()
    uow, limiter = _world(user)

    await _update(user, "anna", uow, limiter)

    assert uow.calls == [
        "get_membership",
        "get_for_update",
        "lock",
        "get_owner",
        "get_release",
        "change",
        "commit",
    ]


async def test_nickname_is_changed() -> None:
    user = make_user(nickname="anna")
    uow, limiter = _world(user)

    found = await _update(user, "boris", uow, limiter)

    assert found == replace(user, nickname="boris")
    assert uow.changes == [(user.id, "anna", "boris")]
    assert uow.commits == 1


async def test_change_locks_both_nicknames() -> None:
    user = make_user(nickname="anna")
    uow, limiter = _world(user)

    await _update(user, "boris", uow, limiter)

    assert uow.locked == [["anna", "boris"]]


async def test_change_spends_the_users_own_limit() -> None:
    user = make_user(nickname="anna")
    uow, limiter = _world(user)

    await _update(user, "boris", uow, limiter)

    assert limiter.hits == [(f"nickname_change:{user.id}", NICKNAME_CHANGE_LIMIT)]


async def test_change_follows_the_safe_order() -> None:
    user = make_user(nickname="anna")
    uow, limiter = _world(user)

    await _update(user, "boris", uow, limiter)

    assert uow.calls == [
        "get_membership",
        "get_for_update",
        "lock",
        "get_owner",
        "get_release",
        "hit",
        "change",
        "commit",
    ]
    assert limiter.hit_inside_uow == [True]


@pytest.mark.parametrize("raw", ["anna", "ANNA", " Anna "])
async def test_same_nickname_changes_nothing(raw: str) -> None:
    user = make_user(nickname="anna")
    uow, limiter = _world(user)

    found = await _update(user, raw, uow, limiter)

    assert found == user
    assert uow.calls == ["get_membership"]
    assert limiter.hits == []


async def test_invalid_nickname_is_rejected_before_anything_else() -> None:
    user = make_user(nickname="anna")
    uow, limiter = _world(user)

    with pytest.raises(InvalidNicknameError) as caught:
        await _update(user, "ab", uow, limiter)

    assert caught.value.reason == "too_short"
    assert "get_for_update" not in uow.calls
    assert limiter.hits == []


async def test_stale_session_user_is_reread_before_deciding() -> None:
    stored = make_user(nickname="anna")
    stale = replace(stored, nickname=None, display_name="Old name")
    uow, limiter = _world(stored)

    found = await _update(stale, "boris", uow, limiter)

    assert found == replace(stored, nickname="boris")
    assert uow.changes == [(stored.id, "anna", "boris")]
    assert uow.locked == [["anna", "boris"]]
    assert len(limiter.hits) == 1


async def test_nickname_already_set_by_parallel_request_changes_nothing() -> None:
    stored = make_user(nickname="boris")
    stale = replace(stored, nickname="anna")
    uow, limiter = _world(stored)

    found = await _update(stale, "boris", uow, limiter)

    assert found == stored
    assert uow.changes == []
    assert uow.commits == 0
    assert limiter.hits == []


async def test_user_deleted_after_authentication_is_rejected() -> None:
    ghost = make_user(nickname="anna")
    uow, limiter = _world()
    uow.memberships[ghost.id] = MEMBERSHIP

    with pytest.raises(NotAuthenticatedError):
        await _update(ghost, "boris", uow, limiter)

    assert uow.changes == []
    assert uow.commits == 0


async def test_nickname_of_another_user_is_taken() -> None:
    owner = make_user("Owner", nickname="boris")
    user = make_user(nickname="anna")
    uow, limiter = _world(owner, user)

    with pytest.raises(NicknameTakenError):
        await _update(user, "Boris", uow, limiter)

    assert uow.changes == []
    assert uow.commits == 0
    assert limiter.hits == []


@pytest.mark.parametrize(
    "ago", [timedelta(0), timedelta(days=29, hours=23)], ids=["just_now", "almost_month"]
)
async def test_nickname_in_someone_elses_quarantine_is_taken(ago: timedelta) -> None:
    user = make_user(nickname="anna")
    uow, limiter = _world(user, releases={"boris": _released(uuid.uuid7(), ago)})

    with pytest.raises(NicknameTakenError):
        await _update(user, "boris", uow, limiter)

    assert uow.changes == []
    assert limiter.hits == []


async def test_nickname_of_deleted_account_in_quarantine_is_taken() -> None:
    user = make_user()
    uow, limiter = _world(user, releases={"boris": _released(None, timedelta(days=1))})

    with pytest.raises(NicknameTakenError):
        await _update(user, "boris", uow, limiter)


async def test_own_quarantined_nickname_can_be_taken_back() -> None:
    user = make_user(nickname="boris")
    uow, limiter = _world(user, releases={"anna": _released(user.id, timedelta(hours=1))})

    found = await _update(user, "anna", uow, limiter)

    assert found.nickname == "anna"
    assert uow.changes == [(user.id, "boris", "anna")]


async def test_quarantine_is_judged_by_the_given_moment() -> None:
    user = make_user()
    uow, limiter = _world(user, releases={"boris": _released(uuid.uuid7(), timedelta(days=31))})

    found = await _update(user, "boris", uow, limiter)

    assert found.nickname == "boris"


async def test_exceeded_limit_reports_wait_and_changes_nothing() -> None:
    user = make_user(nickname="anna")
    uow, limiter = _world(user, retry_after=3600)

    with pytest.raises(RateLimitedError) as caught:
        await _update(user, "boris", uow, limiter)

    assert caught.value.retry_after_seconds == 3600
    assert uow.changes == []
    assert uow.commits == 0
    assert uow.active is False


async def test_limiter_outage_is_reported_and_changes_nothing() -> None:
    user = make_user(nickname="anna")
    outage = DependencyUnavailableError("Rate limiter is unavailable")
    uow, limiter = _world(user, failure=outage)

    with pytest.raises(DependencyUnavailableError) as caught:
        await _update(user, "boris", uow, limiter)

    assert caught.value is outage
    assert uow.changes == []
    assert uow.commits == 0
