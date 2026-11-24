import asyncio
import json
import logging
import uuid
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from http.cookiejar import CookieJar, DefaultCookiePolicy
from http.cookies import SimpleCookie
from typing import Any

import argon2
import httpx
import pytest
import structlog
from fakes import FakeBreachChecker
from fastapi import FastAPI
from redis.asyncio import Redis
from sqlalchemy import text

from app.core.config import get_settings
from app.core.db import get_engine, get_session_factory
from app.core.redis import get_redis
from app.modules.identity.domain.enums import TokenPurpose
from app.modules.identity.infrastructure.models import PasswordCredential, User
from app.modules.identity.infrastructure.redis_one_time_token_store import RedisOneTimeTokenStore
from app.modules.identity.routes.dependencies import (
    get_breach_checker,
    get_one_time_token_store,
)

FORGOT = "/api/v1/auth/password/forgot"
RESET = "/api/v1/auth/password/reset"
CHANGE = "/api/v1/auth/password/change"
LOGIN = "/api/v1/auth/login"
LOGOUT = "/api/v1/auth/logout"
REGISTER = "/api/v1/auth/register"
ME = "/api/v1/users/me"
PROBLEM_JSON = "application/problem+json"
OLD_PASSWORD = "correct horse battery"
NEW_PASSWORD = "brand new horse battery"
VERIFIED_AT = datetime(2026, 11, 20, 12, 0, tzinfo=UTC)


def _client_from(app: FastAPI, ip: str = "127.0.0.1") -> httpx.AsyncClient:
    transport = httpx.ASGITransport(app, raise_app_exceptions=False, client=(ip, 5000))
    jar = CookieJar(policy=DefaultCookiePolicy(allowed_domains=[]))
    return httpx.AsyncClient(transport=transport, base_url="http://test", cookies=jar)


@pytest.fixture
async def client(app: FastAPI) -> AsyncIterator[httpx.AsyncClient]:
    async with _client_from(app) as instance:
        yield instance


@pytest.fixture
def breach(app: FastAPI) -> FakeBreachChecker:
    checker = FakeBreachChecker(False)
    app.dependency_overrides[get_breach_checker] = lambda: checker
    return checker


async def _account(
    email: str = "anna@example.org", password: str | None = OLD_PASSWORD, verified: bool = True
) -> uuid.UUID:
    async with get_session_factory()() as session:
        user = User(
            email=email,
            display_name="Anna",
            avatar_url=None,
            email_verified_at=VERIFIED_AT if verified else None,
        )
        session.add(user)
        await session.flush()
        if password is not None:
            hashed = argon2.PasswordHasher().hash(password)
            session.add(PasswordCredential(user_id=user.id, password_hash=hashed))
        await session.commit()
        return user.id


async def _post(
    client: httpx.AsyncClient, path: str, body: dict[str, Any], session: str | None = None
) -> httpx.Response:
    headers = {"Content-Type": "application/json"}
    if session is not None:
        headers["Cookie"] = f"{get_settings().session.cookie_name}={session}"
    return await client.post(path, content=json.dumps(body), headers=headers)


def _cookie(response: httpx.Response) -> Any:
    headers = response.headers.get_list("set-cookie")
    assert len(headers) == 1
    jar: SimpleCookie = SimpleCookie()
    jar.load(headers[0])
    return jar[get_settings().session.cookie_name]


async def _sign_in(
    client: httpx.AsyncClient, email: str = "anna@example.org", password: str = OLD_PASSWORD
) -> str:
    response = await _post(client, LOGIN, {"email": email, "password": password})
    assert response.status_code == 204
    value: str = _cookie(response).value
    return value


async def _me(client: httpx.AsyncClient, session: str) -> int:
    cookie = {"Cookie": f"{get_settings().session.cookie_name}={session}"}
    return (await client.get(ME, headers=cookie)).status_code


async def _reset_token(
    user_id: uuid.UUID, purpose: TokenPurpose = TokenPurpose.PASSWORD_RESET
) -> str:
    version = await _version(user_id)
    store = RedisOneTimeTokenStore(client=get_redis(), operation_timeout_seconds=1.0)
    return await store.issue(purpose, user_id, version, timedelta(hours=1))


async def _version(user_id: uuid.UUID) -> int:
    async with get_engine().connect() as connection:
        value = await connection.scalar(
            text("SELECT credentials_version FROM users WHERE id = :id"), {"id": user_id}
        )
    return int(value)


async def _verified(user_id: uuid.UUID) -> bool:
    async with get_engine().connect() as connection:
        value = await connection.scalar(
            text("SELECT email_verified_at FROM users WHERE id = :id"), {"id": user_id}
        )
    return value is not None


async def _jobs() -> list[tuple[str, uuid.UUID]]:
    async with get_engine().connect() as connection:
        rows = await connection.execute(text("SELECT purpose::text, user_id FROM email_jobs"))
    return sorted((str(row[0]), row[1]) for row in rows)


async def _logs_in(client: httpx.AsyncClient, password: str) -> int:
    body = {"email": "anna@example.org", "password": password}
    return (await _post(client, LOGIN, body)).status_code


def _without_request_id(response: httpx.Response) -> dict[str, Any]:
    body: dict[str, Any] = response.json()
    body.pop("request_id")
    return body


async def test_forgot_for_known_email_queues_a_reset_letter(client: httpx.AsyncClient) -> None:
    user_id = await _account()

    response = await _post(client, FORGOT, {"email": "ANNA@example.org"})

    assert response.status_code == 202
    assert response.content == b""
    assert response.headers["cache-control"] == "no-store"
    assert await _jobs() == [("password_reset", user_id)]


async def test_forgot_answers_the_same_for_unknown_email(client: httpx.AsyncClient) -> None:
    await _account()

    known = await _post(client, FORGOT, {"email": "anna@example.org"})
    unknown = await _post(client, FORGOT, {"email": "nobody@example.org"})

    assert (unknown.status_code, unknown.content) == (known.status_code, known.content)
    assert [purpose for purpose, _ in await _jobs()] == ["password_reset"]


@pytest.mark.parametrize(
    ("password", "verified"),
    [(None, True), (OLD_PASSWORD, False)],
    ids=["google_only", "unverified"],
)
async def test_forgot_reaches_every_kind_of_account(
    client: httpx.AsyncClient, password: str | None, verified: bool
) -> None:
    user_id = await _account(password=password, verified=verified)

    await _post(client, FORGOT, {"email": "anna@example.org"})

    assert await _jobs() == [("password_reset", user_id)]


async def test_sixth_forgot_on_one_email_is_429(client: httpx.AsyncClient) -> None:
    await _account()

    statuses = [
        (await _post(client, FORGOT, {"email": "anna@example.org"})).status_code for _ in range(6)
    ]

    assert statuses == [202] * 5 + [429]


async def test_forgot_has_its_own_counter(
    client: httpx.AsyncClient, breach: FakeBreachChecker
) -> None:
    for _ in range(5):
        await _post(client, FORGOT, {"email": "anna@example.org"})

    response = await _post(
        client,
        REGISTER,
        {"email": "anna@example.org", "password": OLD_PASSWORD, "display_name": "Anna"},
    )

    assert response.status_code == 202


async def test_reset_sets_the_new_password_and_signs_everyone_out(
    client: httpx.AsyncClient, breach: FakeBreachChecker
) -> None:
    user_id = await _account()
    await _account("boris@example.org")
    laptop = await _sign_in(client)
    phone = await _sign_in(client)
    neighbour = await _sign_in(client, "boris@example.org")
    token = await _reset_token(user_id)

    response = await _post(client, RESET, {"token": token, "password": NEW_PASSWORD})

    assert response.status_code == 204
    assert response.content == b""
    assert response.headers["cache-control"] == "no-store"
    assert "set-cookie" not in response.headers
    assert await _me(client, laptop) == 401
    assert await _me(client, phone) == 401
    assert await _me(client, neighbour) == 200
    assert await _version(user_id) == 1
    assert await _logs_in(client, NEW_PASSWORD) == 204
    assert await _logs_in(client, OLD_PASSWORD) == 401
    assert await _me(client, await _sign_in(client, password=NEW_PASSWORD)) == 200


async def test_reset_confirms_the_email(
    client: httpx.AsyncClient, breach: FakeBreachChecker
) -> None:
    user_id = await _account(verified=False)
    token = await _reset_token(user_id)

    await _post(client, RESET, {"token": token, "password": NEW_PASSWORD})

    assert await _verified(user_id)
    assert await _logs_in(client, NEW_PASSWORD) == 204


async def test_reset_link_works_only_once(
    client: httpx.AsyncClient, breach: FakeBreachChecker
) -> None:
    user_id = await _account()
    token = await _reset_token(user_id)
    await _post(client, RESET, {"token": token, "password": NEW_PASSWORD})

    again = await _post(client, RESET, {"token": token, "password": "another new passphrase"})

    assert again.status_code == 422
    assert again.json()["type"] == "/problems/token-invalid"
    assert await _logs_in(client, NEW_PASSWORD) == 204


async def test_every_older_link_dies_with_the_reset(
    client: httpx.AsyncClient, breach: FakeBreachChecker
) -> None:
    user_id = await _account()
    first = await _reset_token(user_id)
    second = await _reset_token(user_id)

    used = await _post(client, RESET, {"token": first, "password": NEW_PASSWORD})
    stale = await _post(client, RESET, {"token": second, "password": "another new passphrase"})

    assert used.status_code == 204
    assert stale.status_code == 422
    assert stale.json()["type"] == "/problems/token-invalid"


async def test_double_click_on_one_link_succeeds_once(
    client: httpx.AsyncClient, breach: FakeBreachChecker
) -> None:
    user_id = await _account()
    token = await _reset_token(user_id)

    responses = await asyncio.gather(
        *(_post(client, RESET, {"token": token, "password": NEW_PASSWORD}) for _ in range(3))
    )

    assert sorted(response.status_code for response in responses) == [204, 422, 422]
    assert await _version(user_id) == 1


@pytest.mark.parametrize(
    ("password", "reason", "answer"),
    [
        ("short", "too_short", False),
        ("brand \ud800 horse battery", "bad_characters", False),
        (NEW_PASSWORD, "breached", True),
    ],
    ids=["too_short", "lone_surrogate", "breached"],
)
async def test_weak_password_keeps_the_link_working(
    client: httpx.AsyncClient,
    breach: FakeBreachChecker,
    password: str,
    reason: str,
    answer: bool,
) -> None:
    user_id = await _account()
    token = await _reset_token(user_id)
    breach.answer = answer

    refused = await _post(client, RESET, {"token": token, "password": password})
    breach.answer = False
    accepted = await _post(client, RESET, {"token": token, "password": "a good new passphrase"})

    assert refused.status_code == 422
    assert refused.json()["type"] == "/problems/password-weak"
    assert refused.json()["errors"][0]["type"] == reason
    assert accepted.status_code == 204


async def test_unknown_token_costs_no_breach_check(
    client: httpx.AsyncClient, breach: FakeBreachChecker
) -> None:
    await _account()

    response = await _post(client, RESET, {"token": "A" * 43, "password": NEW_PASSWORD})

    assert response.status_code == 422
    assert response.json()["type"] == "/problems/token-invalid"
    assert breach.passwords == []


async def test_confirmation_token_is_not_a_reset_token(
    client: httpx.AsyncClient, breach: FakeBreachChecker
) -> None:
    user_id = await _account()
    token = await _reset_token(user_id, TokenPurpose.EMAIL_CONFIRM)

    response = await _post(client, RESET, {"token": token, "password": NEW_PASSWORD})

    assert response.status_code == 422
    assert await _logs_in(client, OLD_PASSWORD) == 204


async def test_reset_gives_a_google_only_account_a_password(
    client: httpx.AsyncClient, breach: FakeBreachChecker
) -> None:
    user_id = await _account(password=None)
    token = await _reset_token(user_id)

    response = await _post(client, RESET, {"token": token, "password": NEW_PASSWORD})

    assert response.status_code == 204
    assert await _logs_in(client, NEW_PASSWORD) == 204


async def test_reset_with_token_store_down_is_503(
    app: FastAPI, client: httpx.AsyncClient, breach: FakeBreachChecker, dead_redis: Redis
) -> None:
    await _account()
    app.dependency_overrides[get_one_time_token_store] = lambda: RedisOneTimeTokenStore(
        client=dead_redis, operation_timeout_seconds=0.5
    )

    response = await _post(client, RESET, {"token": "A" * 43, "password": NEW_PASSWORD})

    assert response.status_code == 503
    assert response.headers["content-type"] == PROBLEM_JSON


async def test_change_needs_a_session(client: httpx.AsyncClient) -> None:
    response = await _post(
        client, CHANGE, {"current_password": OLD_PASSWORD, "new_password": NEW_PASSWORD}
    )

    assert response.status_code == 401


async def test_change_keeps_this_device_signed_in_and_signs_out_the_others(
    client: httpx.AsyncClient, breach: FakeBreachChecker
) -> None:
    user_id = await _account()
    phone = await _sign_in(client)
    laptop = await _sign_in(client)

    response = await _post(
        client,
        CHANGE,
        {"current_password": OLD_PASSWORD, "new_password": NEW_PASSWORD},
        session=laptop,
    )

    assert response.status_code == 204
    assert response.headers["cache-control"] == "no-store"
    morsel = _cookie(response)
    assert morsel["max-age"] == str(get_settings().session.absolute_ttl_seconds)
    assert morsel["httponly"] is True
    assert await _me(client, morsel.value) == 200
    assert await _me(client, laptop) == 401
    assert await _me(client, phone) == 401
    assert await _version(user_id) == 1
    assert await _logs_in(client, NEW_PASSWORD) == 204
    assert await _logs_in(client, OLD_PASSWORD) == 401


async def test_wrong_current_password_keeps_everything(
    client: httpx.AsyncClient, breach: FakeBreachChecker
) -> None:
    user_id = await _account()
    session = await _sign_in(client)

    response = await _post(
        client,
        CHANGE,
        {"current_password": "wrong horse battery", "new_password": NEW_PASSWORD},
        session=session,
    )

    assert response.status_code == 401
    assert response.json()["type"] == "/problems/invalid-credentials"
    assert "set-cookie" not in response.headers
    assert await _me(client, session) == 200
    assert await _version(user_id) == 0


async def test_current_password_of_invalid_format_answers_like_a_wrong_one(
    client: httpx.AsyncClient, breach: FakeBreachChecker
) -> None:
    await _account()
    session = await _sign_in(client)

    wrong = await _post(
        client,
        CHANGE,
        {"current_password": "wrong horse battery", "new_password": NEW_PASSWORD},
        session=session,
    )
    short = await _post(
        client, CHANGE, {"current_password": "short", "new_password": NEW_PASSWORD}, session=session
    )

    assert _without_request_id(short) == _without_request_id(wrong)


async def test_sixth_change_attempt_in_an_hour_is_429(
    client: httpx.AsyncClient, breach: FakeBreachChecker
) -> None:
    await _account()
    session = await _sign_in(client)
    body = {"current_password": "wrong horse battery", "new_password": NEW_PASSWORD}

    statuses = [(await _post(client, CHANGE, body, session=session)).status_code for _ in range(6)]

    assert statuses == [401] * 5 + [429]


async def test_format_errors_do_not_spend_change_attempts(
    client: httpx.AsyncClient, breach: FakeBreachChecker
) -> None:
    await _account()
    session = await _sign_in(client)
    for _ in range(6):
        await _post(
            client,
            CHANGE,
            {"current_password": "short", "new_password": NEW_PASSWORD},
            session=session,
        )
        await _post(
            client,
            CHANGE,
            {"current_password": OLD_PASSWORD, "new_password": "short"},
            session=session,
        )

    response = await _post(
        client,
        CHANGE,
        {"current_password": OLD_PASSWORD, "new_password": NEW_PASSWORD},
        session=session,
    )

    assert response.status_code == 204


async def test_account_without_password_is_told_to_use_the_reset(
    client: httpx.AsyncClient, breach: FakeBreachChecker
) -> None:
    user_id = await _account()
    session = await _sign_in(client)
    async with get_engine().begin() as connection:
        await connection.execute(
            text("DELETE FROM password_credentials WHERE user_id = :id"), {"id": user_id}
        )

    response = await _post(
        client,
        CHANGE,
        {"current_password": OLD_PASSWORD, "new_password": NEW_PASSWORD},
        session=session,
    )

    assert response.status_code == 409
    assert response.json()["type"] == "/problems/password-not-set"


@pytest.mark.parametrize(
    ("new", "reason", "answer"),
    [("short", "too_short", False), (NEW_PASSWORD, "breached", True)],
    ids=["too_short", "breached"],
)
async def test_weak_new_password_is_422_and_keeps_the_old_one(
    client: httpx.AsyncClient, breach: FakeBreachChecker, new: str, reason: str, answer: bool
) -> None:
    await _account()
    session = await _sign_in(client)
    breach.answer = answer

    response = await _post(
        client, CHANGE, {"current_password": OLD_PASSWORD, "new_password": new}, session=session
    )

    assert response.status_code == 422
    assert response.json()["errors"][0]["type"] == reason
    assert await _me(client, session) == 200


@pytest.mark.parametrize(
    ("path", "body"),
    [
        (FORGOT, {"email": "anna@example.org"}),
        (RESET, {"token": "A" * 43, "password": NEW_PASSWORD}),
        (CHANGE, {"current_password": OLD_PASSWORD, "new_password": NEW_PASSWORD}),
    ],
    ids=["forgot", "reset", "change"],
)
@pytest.mark.parametrize("kind", ["text_plain", "unknown_field"])
async def test_malformed_requests_are_422(
    client: httpx.AsyncClient,
    breach: FakeBreachChecker,
    path: str,
    body: dict[str, str],
    kind: str,
) -> None:
    await _account()
    session = await _sign_in(client)
    cookie = f"{get_settings().session.cookie_name}={session}"
    if kind == "text_plain":
        headers = {"Content-Type": "text/plain", "Cookie": cookie}
        content = json.dumps(body)
    else:
        headers = {"Content-Type": "application/json", "Cookie": cookie}
        content = json.dumps(body | {"extra": "field"})

    response = await client.post(path, content=content, headers=headers)

    assert response.status_code == 422
    assert response.json()["type"] == "/problems/validation-error"


async def test_secrets_never_reach_the_logs(
    client: httpx.AsyncClient, breach: FakeBreachChecker, caplog: pytest.LogCaptureFixture
) -> None:
    user_id = await _account()
    caplog.set_level(logging.DEBUG)

    with structlog.testing.capture_logs() as records:
        await _post(client, FORGOT, {"email": "anna@example.org"})
        token = await _reset_token(user_id)
        await _post(client, RESET, {"token": token, "password": NEW_PASSWORD})
        session = await _sign_in(client, password=NEW_PASSWORD)
        await _post(
            client,
            CHANGE,
            {"current_password": NEW_PASSWORD, "new_password": "the third passphrase"},
            session=session,
        )

    everything = (repr(records) + caplog.text).lower()
    assert "anna@" not in everything
    assert "horse" not in everything
    assert "passphrase" not in everything
    assert token.lower() not in everything
    assert session.lower() not in everything
    events = [record["event"] for record in records if record["event"].startswith("security.")]
    assert {
        "security.password_reset_requested",
        "security.password_reset_completed",
        "security.password_changed",
    } <= set(events)


def test_openapi_documents_the_password_endpoints(app: FastAPI) -> None:
    paths = app.openapi()["paths"]

    assert {"202", "422", "429", "503"} <= set(paths[FORGOT]["post"]["responses"])
    assert {"204", "422", "503"} <= set(paths[RESET]["post"]["responses"])
    assert {"204", "401", "409", "422", "429", "503"} <= set(paths[CHANGE]["post"]["responses"])
    for path in (FORGOT, RESET, CHANGE):
        assert paths[path]["post"]["summary"]
