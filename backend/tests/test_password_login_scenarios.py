import uuid
from contextlib import suppress
from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest
from fakes import FakeEvents, FakeHasher, FakeLimiter, FakeSessions, FakeUnitOfWork, make_user

from app.core.exceptions import AppError, DependencyUnavailableError, RateLimitedError
from app.modules.identity.domain.emails import email_fingerprint
from app.modules.identity.domain.exceptions import EmailNotVerifiedError, InvalidCredentialsError
from app.modules.identity.domain.limits import LOGIN_EMAIL_LIMIT, LOGIN_IP_LIMIT
from app.modules.identity.service.dto import LoginDTO, UserDTO
from app.modules.identity.service.password_login import PasswordLoginService

SECRET = b"login-secret"
PASSWORD = "correct horse battery"
STORED_HASH = "$argon2id$stored"
CURRENT_TOKEN = "C" * 43
VERIFIED_AT = datetime(2026, 11, 20, 12, 0, tzinfo=UTC)
LOGIN = LoginDTO(
    email="Anna@Example.org",
    password=PASSWORD,
    client_ip="203.0.113.7",
    current_token=None,
)
IP_KEY = "login_ip:203.0.113.7"
EMAIL_KEY = "login_email:" + email_fingerprint("anna@example.org", SECRET)


def _anna(verified: bool = True) -> UserDTO:
    return replace(
        make_user("Anna"),
        email="anna@example.org",
        email_verified_at=VERIFIED_AT if verified else None,
    )


class World:
    def __init__(
        self,
        user: UserDTO | None = None,
        password_hash: str | None = STORED_HASH,
        outdated: bool = False,
        retry_after: int | None = None,
        limiter_failure: Exception | None = None,
        sessions_failure: Exception | None = None,
    ) -> None:
        self.user = user
        self.uow = FakeUnitOfWork([user] if user else [])
        if user is not None and password_hash is not None:
            self.uow.password_hashes[user.id] = password_hash
        self.limiter = FakeLimiter(self.uow, retry_after=retry_after, failure=limiter_failure)
        self.hasher = FakeHasher(
            self.uow,
            accepted={STORED_HASH: PASSWORD},
            outdated={STORED_HASH} if outdated else (),
        )
        self.sessions = FakeSessions(
            self.uow, live={CURRENT_TOKEN: uuid.uuid7()}, failure=sessions_failure
        )
        self.events = FakeEvents()
        self.service = PasswordLoginService(
            uow=self.uow,
            limiter=self.limiter,
            hasher=self.hasher,
            sessions=self.sessions,
            events=self.events,
            secret=SECRET,
        )

    async def login(self, login: LoginDTO = LOGIN) -> str:
        return await self.service.login(login)

    async def refused(self, login: LoginDTO = LOGIN) -> AppError:
        with pytest.raises(AppError) as caught:
            await self.service.login(login)
        return caught.value


def test_login_dto_hides_password_and_session_token() -> None:
    login = replace(LOGIN, current_token=CURRENT_TOKEN)

    assert PASSWORD not in repr(login)
    assert CURRENT_TOKEN not in repr(login)
    assert "Anna@Example.org" in repr(login)


async def test_right_password_opens_a_new_session_for_the_user() -> None:
    world = World(_anna())

    token = await world.login()

    assert world.user is not None
    assert world.sessions.created == [(world.user.id, token)]
    assert world.sessions.live[token] == world.user.id
    assert world.events.recorded == [("login_succeeded", str(world.user.id), "password")]


async def test_new_session_carries_the_current_credentials_version() -> None:
    world = World(replace(_anna(), credentials_version=6))

    token = await world.login()

    assert world.sessions.versions[token] == 6


async def test_successful_login_without_rehash_writes_nothing() -> None:
    world = World(_anna())

    await world.login()

    assert world.uow.commits == 0
    assert "set_hash" not in world.uow.calls
    assert world.hasher.passwords == []


async def test_current_session_of_the_browser_is_revoked_before_the_new_one() -> None:
    world = World(_anna())

    token = await world.login(replace(LOGIN, current_token=CURRENT_TOKEN))

    assert world.sessions.revoked == [CURRENT_TOKEN]
    assert CURRENT_TOKEN not in world.sessions.live
    assert world.sessions.order == ["revoke_session", "create_session"]
    assert token != CURRENT_TOKEN


async def test_login_without_current_session_revokes_nothing() -> None:
    world = World(_anna())

    await world.login()

    assert world.sessions.revoked == []


async def test_limits_are_counted_by_ip_then_by_email_fingerprint() -> None:
    world = World(_anna())

    await world.login()

    assert world.limiter.hits == [(IP_KEY, LOGIN_IP_LIMIT), (EMAIL_KEY, LOGIN_EMAIL_LIMIT)]


def test_login_limits_are_ten_per_email_and_thirty_per_ip_in_fifteen_minutes() -> None:
    assert (LOGIN_EMAIL_LIMIT.limit, LOGIN_EMAIL_LIMIT.window) == (10, timedelta(minutes=15))
    assert (LOGIN_IP_LIMIT.limit, LOGIN_IP_LIMIT.window) == (30, timedelta(minutes=15))


@pytest.mark.parametrize("email", ["anna@example.org", "ANNA@EXAMPLE.ORG"])
async def test_email_limit_key_ignores_case(email: str) -> None:
    world = World(_anna())

    await world.login(replace(LOGIN, email=email))

    assert world.limiter.hits[1][0] == EMAIL_KEY


async def test_limit_keys_reveal_no_email() -> None:
    world = World(_anna())

    await world.login()

    assert all("anna" not in key.lower() for key, _ in world.limiter.hits)


async def test_email_limit_key_is_keyed_by_the_secret() -> None:
    world = World(_anna())
    world.service = PasswordLoginService(
        uow=world.uow,
        limiter=world.limiter,
        hasher=world.hasher,
        sessions=world.sessions,
        events=world.events,
        secret=b"another-secret",
    )

    await world.login()

    assert world.limiter.hits[1][0] == "login_email:" + email_fingerprint(
        "anna@example.org", b"another-secret"
    )


async def test_unknown_client_address_shares_one_ip_key() -> None:
    world = World(_anna())

    await world.login(replace(LOGIN, client_ip=None))

    assert world.limiter.hits[0][0] == "login_ip:unknown"


@pytest.mark.parametrize(
    ("scope", "refusing", "hits"), [("ip", "login_ip:", 1), ("email", "login_email:", 2)]
)
async def test_exceeded_limit_is_429_before_anything_is_read(
    scope: str, refusing: str, hits: int
) -> None:
    world = World(_anna(), retry_after=120)
    world.limiter.refusing = refusing

    refusal = await world.refused()

    assert isinstance(refusal, RateLimitedError)
    assert refusal.retry_after_seconds == 120
    assert len(world.limiter.hits) == hits
    assert world.events.recorded == [("rate_limited", "login", scope)]
    assert world.uow.calls == ["hit"] * hits
    assert world.hasher.verified == []
    assert world.hasher.dummies == []
    assert world.sessions.created == []


async def test_limiter_outage_is_reported_before_anything_is_read() -> None:
    outage = DependencyUnavailableError("Rate limiter is unavailable")
    world = World(_anna(), limiter_failure=outage)

    refusal = await world.refused()

    assert refusal is outage
    assert world.uow.calls == ["hit"]
    assert world.sessions.created == []


async def test_unknown_email_spends_a_dummy_check_and_is_refused() -> None:
    world = World()

    refusal = await world.refused()

    assert isinstance(refusal, InvalidCredentialsError)
    assert world.hasher.dummies == [PASSWORD]
    assert world.hasher.verified == []
    assert world.events.recorded == [("login_failed", "-", "bad_credentials")]
    assert world.sessions.created == []


async def test_account_without_password_spends_a_dummy_check_and_is_refused() -> None:
    world = World(_anna(), password_hash=None)

    refusal = await world.refused()

    assert world.user is not None
    assert isinstance(refusal, InvalidCredentialsError)
    assert world.hasher.dummies == [PASSWORD]
    assert world.hasher.verified == []
    assert world.events.recorded == [("login_failed", str(world.user.id), "bad_credentials")]
    assert world.sessions.created == []


async def test_wrong_password_is_refused_without_a_dummy_check() -> None:
    world = World(_anna())

    refusal = await world.refused(replace(LOGIN, password="wrong horse battery"))

    assert isinstance(refusal, InvalidCredentialsError)
    assert world.hasher.verified == [(STORED_HASH, "wrong horse battery")]
    assert world.user is not None
    assert world.hasher.dummies == []
    assert world.events.recorded == [("login_failed", str(world.user.id), "bad_credentials")]
    assert world.sessions.created == []


async def test_failed_login_keeps_the_current_session() -> None:
    world = World(_anna())

    await world.refused(replace(LOGIN, password="wrong horse battery", current_token=CURRENT_TOKEN))

    assert world.sessions.revoked == []
    assert CURRENT_TOKEN in world.sessions.live


@pytest.mark.parametrize(
    "password",
    ["short", "        ", "x" * 129, "correct horse \ud800"],
    ids=["too_short", "blank", "too_long", "lone_surrogate"],
)
async def test_password_of_invalid_format_is_bad_credentials_before_limits(
    password: str,
) -> None:
    world = World(_anna())

    refusal = await world.refused(replace(LOGIN, password=password))

    assert isinstance(refusal, InvalidCredentialsError)
    assert world.limiter.hits == []
    assert world.uow.calls == []
    assert world.hasher.verified == []
    assert world.hasher.dummies == []
    assert world.sessions.created == []


async def test_every_bad_credentials_refusal_looks_the_same() -> None:
    refusals = [
        await World().refused(),
        await World(_anna(), password_hash=None).refused(),
        await World(_anna()).refused(replace(LOGIN, password="wrong horse battery")),
        await World(_anna()).refused(replace(LOGIN, password="short")),
    ]

    assert {type(refusal) for refusal in refusals} == {InvalidCredentialsError}
    assert {str(refusal) for refusal in refusals} == {"Email or password is incorrect"}


async def test_unverified_email_with_right_password_is_403() -> None:
    world = World(_anna(verified=False))

    refusal = await world.refused()

    assert world.user is not None
    assert isinstance(refusal, EmailNotVerifiedError)
    assert world.events.recorded == [("login_failed", str(world.user.id), "email_not_verified")]
    assert world.sessions.created == []
    assert world.uow.commits == 0


async def test_unverified_email_with_wrong_password_is_bad_credentials() -> None:
    world = World(_anna(verified=False))

    refusal = await world.refused(replace(LOGIN, password="wrong horse battery"))

    assert world.user is not None
    assert isinstance(refusal, InvalidCredentialsError)
    assert world.events.recorded == [("login_failed", str(world.user.id), "bad_credentials")]


async def test_password_is_checked_in_normalized_form() -> None:
    world = World(_anna())

    await world.login(replace(LOGIN, password="ｃｏｒｒｅｃｔ horse battery"))

    assert world.hasher.verified == [(STORED_HASH, PASSWORD)]
    assert len(world.sessions.created) == 1


async def test_outdated_hash_is_replaced_in_a_committed_transaction() -> None:
    world = World(_anna(), outdated=True)

    await world.login(replace(LOGIN, password="ｃｏｒｒｅｃｔ horse battery"))

    assert world.user is not None
    assert world.hasher.passwords == [PASSWORD]
    assert world.uow.password_hashes[world.user.id] == "$argon2id$fake$1"
    assert world.uow.commits == 1
    assert world.uow.calls.index("set_hash") < world.uow.calls.index("commit")
    assert len(world.sessions.created) == 1


async def test_outdated_hash_of_unverified_account_is_left_alone() -> None:
    world = World(_anna(verified=False), outdated=True)

    await world.refused()

    assert world.hasher.passwords == []
    assert world.uow.commits == 0


async def test_argon2_never_runs_while_a_transaction_is_open() -> None:
    for world, login in [
        (World(_anna(), outdated=True), LOGIN),
        (World(), LOGIN),
        (World(_anna(), password_hash=None), LOGIN),
        (World(_anna()), replace(LOGIN, password="wrong horse battery")),
    ]:
        with suppress(InvalidCredentialsError):
            await world.login(login)

        assert world.hasher.inside_uow
        assert not any(world.hasher.inside_uow)


async def test_session_store_outage_is_reported_and_nothing_is_logged_as_success() -> None:
    outage = DependencyUnavailableError("Session store is unavailable")
    world = World(_anna(), sessions_failure=outage)

    refusal = await world.refused()

    assert refusal is outage
    assert world.events.recorded == []


async def test_events_carry_no_email_password_or_token() -> None:
    worlds = [World(_anna()), World(), World(_anna(verified=False)), World(_anna())]
    logins = [
        replace(LOGIN, current_token=CURRENT_TOKEN),
        LOGIN,
        LOGIN,
        replace(LOGIN, password="wrong horse battery"),
    ]
    tokens = []
    for world, login in zip(worlds, logins, strict=True):
        with suppress(AppError):
            tokens.append(await world.login(login))

    everything = repr([world.events.recorded for world in worlds]).lower()
    assert "anna" not in everything
    assert "horse" not in everything
    assert CURRENT_TOKEN.lower() not in everything
    assert all(token.lower() not in everything for token in tokens)
