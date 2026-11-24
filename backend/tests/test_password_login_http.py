import asyncio
import json
import logging
import threading
import time
import uuid
from collections.abc import AsyncIterator, Iterator
from datetime import UTC, datetime
from http.cookiejar import CookieJar, DefaultCookiePolicy
from http.cookies import SimpleCookie
from typing import Annotated, Any

import argon2
import httpx
import pytest
import structlog
from fastapi import Depends, FastAPI
from redis.asyncio import Redis
from sqlalchemy import text
from sqlalchemy.pool import QueuePool

from app.core.config import get_settings
from app.core.db import get_engine, get_session_factory
from app.core.redis import get_redis
from app.modules.identity.domain.emails import email_fingerprint
from app.modules.identity.infrastructure.models import PasswordCredential, User
from app.modules.identity.infrastructure.redis_rate_limiter import RedisRateLimiter
from app.modules.identity.infrastructure.redis_session_store import RedisSessionStore
from app.modules.identity.routes.dependencies import (
    get_password_hasher,
    get_password_login_service,
    get_rate_limiter,
    get_secret,
    get_security_events,
    get_session_store,
    get_uow,
)
from app.modules.identity.service.password_login import PasswordLoginService
from app.modules.identity.service.ports import (
    PasswordHasher,
    RateLimiter,
    SecurityEvents,
    SessionStore,
    UnitOfWork,
)

LOGIN = "/api/v1/auth/login"
LOGOUT = "/api/v1/auth/logout"
ME = "/api/v1/users/me"
PROBLEM_JSON = "application/problem+json"
PASSWORD = "correct horse battery"
BODY = {"email": "Anna@Example.org", "password": PASSWORD}
VERIFIED_AT = datetime(2026, 11, 20, 12, 0, tzinfo=UTC)
CURRENT_PARAMETERS = argon2.extract_parameters(argon2.PasswordHasher().hash("probe"))


async def _account(
    email: str = "anna@example.org",
    password: str | None = PASSWORD,
    verified: bool = True,
    password_hash: str | None = None,
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
        if password_hash is None and password is not None:
            password_hash = argon2.PasswordHasher().hash(password)
        if password_hash is not None:
            session.add(PasswordCredential(user_id=user.id, password_hash=password_hash))
        await session.commit()
        return user.id


async def _login(client: httpx.AsyncClient, **overrides: Any) -> httpx.Response:
    return await client.post(
        LOGIN,
        content=json.dumps(BODY | overrides),
        headers={"Content-Type": "application/json"},
    )


def _cookie_name() -> str:
    return get_settings().session.cookie_name


def _session_cookie(response: httpx.Response) -> Any:
    headers = response.headers.get_list("set-cookie")
    assert len(headers) == 1
    jar: SimpleCookie = SimpleCookie()
    jar.load(headers[0])
    assert list(jar) == [_cookie_name()]
    return jar[_cookie_name()]


def _token(response: httpx.Response) -> str:
    value: str = _session_cookie(response).value
    return value


def _with(token: str) -> dict[str, str]:
    return {"Cookie": f"{_cookie_name()}={token}"}


async def _me(client: httpx.AsyncClient, token: str) -> httpx.Response:
    return await client.get(ME, headers=_with(token))


async def _stored_hash(user_id: uuid.UUID) -> str:
    async with get_engine().connect() as connection:
        value = await connection.scalar(
            text("SELECT password_hash FROM password_credentials WHERE user_id = :id"),
            {"id": user_id},
        )
    return str(value)


def _without_request_id(response: httpx.Response) -> dict[str, Any]:
    body: dict[str, Any] = response.json()
    body.pop("request_id")
    return body


def _client_from(app: FastAPI, ip: str = "127.0.0.1") -> httpx.AsyncClient:
    transport = httpx.ASGITransport(app, raise_app_exceptions=False, client=(ip, 5000))
    jar = CookieJar(policy=DefaultCookiePolicy(allowed_domains=[]))
    return httpx.AsyncClient(transport=transport, base_url="http://test", cookies=jar)


@pytest.fixture
async def client(app: FastAPI) -> AsyncIterator[httpx.AsyncClient]:
    async with _client_from(app) as instance:
        yield instance


def _dead_session_store(dead_redis: Redis) -> RedisSessionStore:
    session = get_settings().session
    return RedisSessionStore(
        client=dead_redis,
        idle_ttl_seconds=session.idle_ttl_seconds,
        absolute_ttl_seconds=session.absolute_ttl_seconds,
        operation_timeout_seconds=0.5,
        now=lambda: datetime.now(UTC),
    )


class VerifyRecorder:
    def __init__(self) -> None:
        self.hashes: list[str] = []
        self.checked_out: list[int] = []
        self._real = argon2.PasswordHasher.verify

    def __call__(self, password_hash: str | bytes, password: str | bytes) -> bool:
        pool = get_engine().pool
        assert isinstance(pool, QueuePool)
        self.checked_out.append(pool.checkedout())
        self.hashes.append(str(password_hash))
        return self._real(argon2.PasswordHasher(), password_hash, password)


@pytest.fixture
def verify_calls(monkeypatch: pytest.MonkeyPatch) -> VerifyRecorder:
    recorder = VerifyRecorder()
    monkeypatch.setattr(argon2.PasswordHasher, "verify", recorder)
    return recorder


@pytest.fixture
def secure_cookie(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    monkeypatch.setenv("SESSION__COOKIE_NAME", "__Host-session")
    monkeypatch.setenv("SESSION__COOKIE_SECURE", "true")
    get_settings.cache_clear()

    yield

    get_settings.cache_clear()


async def test_right_password_logs_in(client: httpx.AsyncClient) -> None:
    user_id = await _account()

    response = await _login(client)

    assert response.status_code == 204
    assert response.content == b""
    assert response.headers["cache-control"] == "no-store"
    me = await _me(client, _token(response))
    assert me.status_code == 200
    assert me.json()["id"] == str(user_id)


async def test_session_cookie_lives_thirty_days_with_safe_attributes(
    client: httpx.AsyncClient,
) -> None:
    await _account()

    morsel = _session_cookie(await _login(client))

    assert morsel["max-age"] == str(get_settings().session.absolute_ttl_seconds) == "2592000"
    assert morsel["path"] == "/"
    assert morsel["httponly"] is True
    assert morsel["samesite"].lower() == "lax"
    assert not morsel["secure"]
    assert morsel["domain"] == ""


async def test_secure_settings_give_a_host_only_secure_cookie(
    client: httpx.AsyncClient, secure_cookie: None
) -> None:
    await _account()

    response = await _login(client)

    assert response.status_code == 204
    morsel = _session_cookie(response)
    assert morsel.key == "__Host-session"
    assert morsel["secure"] is True
    assert morsel["path"] == "/"
    assert morsel["domain"] == ""


async def test_login_again_replaces_the_session_of_this_browser(client: httpx.AsyncClient) -> None:
    await _account()
    first = _token(await _login(client))

    second_response = await client.post(LOGIN, json=BODY, headers=_with(first))

    second = _token(second_response)
    assert second != first
    assert (await _me(client, first)).status_code == 401
    assert (await _me(client, second)).status_code == 200


async def test_login_keeps_sessions_of_other_browsers(client: httpx.AsyncClient) -> None:
    await _account()
    phone = _token(await _login(client))

    laptop = _token(await _login(client))

    assert (await _me(client, phone)).status_code == 200
    assert (await _me(client, laptop)).status_code == 200


@pytest.mark.parametrize("cookie", ["garbage", "A" * 43], ids=["malformed", "unknown"])
async def test_dead_cookie_does_not_stop_the_login(client: httpx.AsyncClient, cookie: str) -> None:
    await _account()

    response = await client.post(LOGIN, json=BODY, headers=_with(cookie))

    assert response.status_code == 204
    assert (await _me(client, _token(response))).status_code == 200


async def test_attacker_planted_session_is_revoked_by_the_victims_login(
    client: httpx.AsyncClient,
) -> None:
    await _account("mallory@example.org", "mallory passphrase")
    await _account()
    planted = _token(
        await _login(client, email="mallory@example.org", password="mallory passphrase")
    )

    victim = await client.post(LOGIN, json=BODY, headers=_with(planted))

    assert victim.status_code == 204
    assert (await _me(client, planted)).status_code == 401


async def test_every_bad_credentials_answer_is_the_same(client: httpx.AsyncClient) -> None:
    await _account()
    await _account("google@example.org", password=None)

    responses = [
        await _login(client, password="wrong horse battery"),
        await _login(client, email="nobody@example.org"),
        await _login(client, email="google@example.org"),
        await _login(client, password="short"),
        await _login(client, password="        "),
        await _login(client, password="x" * 129),
        await _login(client, password="correct horse \ud800"),
    ]

    assert {response.status_code for response in responses} == {401}
    assert {response.headers["content-type"] for response in responses} == {PROBLEM_JSON}
    assert {response.headers["www-authenticate"] for response in responses} == {"Cookie"}
    bodies = [_without_request_id(response) for response in responses]
    assert all(body == bodies[0] for body in bodies)
    assert bodies[0]["type"] == "/problems/invalid-credentials"
    assert all("set-cookie" not in response.headers for response in responses)


async def test_unknown_email_costs_a_real_argon2_check(
    client: httpx.AsyncClient, verify_calls: VerifyRecorder
) -> None:
    await _login(client, email="nobody@example.org")

    [dummy] = verify_calls.hashes
    assert argon2.extract_parameters(dummy) == CURRENT_PARAMETERS


async def test_no_database_connection_is_held_while_argon2_runs(
    client: httpx.AsyncClient, verify_calls: VerifyRecorder
) -> None:
    await _account()
    await _account("google@example.org", password=None)

    await _login(client)
    await _login(client, password="wrong horse battery")
    await _login(client, email="nobody@example.org")
    await _login(client, email="google@example.org")

    assert len(verify_calls.checked_out) == 4
    assert set(verify_calls.checked_out) == {0}


async def test_unverified_email_with_right_password_is_403(client: httpx.AsyncClient) -> None:
    await _account(verified=False)

    response = await _login(client)

    assert response.status_code == 403
    assert response.headers["content-type"] == PROBLEM_JSON
    assert response.json()["type"] == "/problems/email-not-verified"
    assert "set-cookie" not in response.headers


async def test_unverified_email_with_wrong_password_is_401(client: httpx.AsyncClient) -> None:
    await _account(verified=False)

    response = await _login(client, password="wrong horse battery")

    assert response.status_code == 401
    assert response.json()["type"] == "/problems/invalid-credentials"


@pytest.mark.parametrize(
    ("email", "password"),
    [
        ("ANNA@EXAMPLE.ORG", PASSWORD),
        ("anna@example.org", "ｃｏｒｒｅｃｔ horse battery"),
    ],
    ids=["email_case", "fullwidth_password"],
)
async def test_equivalent_credentials_log_in(
    client: httpx.AsyncClient, email: str, password: str
) -> None:
    await _account()

    response = await _login(client, email=email, password=password)

    assert response.status_code == 204


@pytest.mark.parametrize(
    "corrupted",
    ["garbage", "мусор", "$argon2id$v=19$m=65536,t=3,p=4$broken"],
    ids=["ascii", "non_ascii", "truncated"],
)
async def test_corrupted_hash_in_database_is_401(client: httpx.AsyncClient, corrupted: str) -> None:
    await _account(password_hash=corrupted)

    response = await _login(client)

    assert response.status_code == 401
    assert response.json()["type"] == "/problems/invalid-credentials"


async def test_outdated_hash_is_upgraded_on_login(client: httpx.AsyncClient) -> None:
    outdated = argon2.PasswordHasher(time_cost=1, memory_cost=8192).hash(PASSWORD)
    user_id = await _account(password_hash=outdated)

    response = await _login(client)

    assert response.status_code == 204
    upgraded = await _stored_hash(user_id)
    assert upgraded != outdated
    assert argon2.extract_parameters(upgraded) == CURRENT_PARAMETERS
    assert argon2.PasswordHasher().verify(upgraded, PASSWORD)


async def test_current_hash_is_left_as_it_is(client: httpx.AsyncClient) -> None:
    user_id = await _account()
    before = await _stored_hash(user_id)

    await _login(client)
    await _login(client)

    assert await _stored_hash(user_id) == before


async def test_outdated_hash_stays_after_a_wrong_password(client: httpx.AsyncClient) -> None:
    outdated = argon2.PasswordHasher(time_cost=1, memory_cost=8192).hash(PASSWORD)
    user_id = await _account(password_hash=outdated)

    await _login(client, password="wrong horse battery")

    assert await _stored_hash(user_id) == outdated


async def test_eleventh_attempt_on_one_email_is_429_in_any_case(
    client: httpx.AsyncClient,
) -> None:
    await _account()
    emails = ["anna@example.org", "ANNA@example.org"] * 5

    with structlog.testing.capture_logs() as records:
        statuses = [
            (await _login(client, email=email, password="wrong horse battery")).status_code
            for email in emails
        ]
        refused = await _login(client)

    assert statuses == [401] * 10
    assert refused.status_code == 429
    assert refused.json()["type"] == "/problems/rate-limited"
    assert 1 <= int(refused.headers["retry-after"]) <= 900
    assert "set-cookie" not in refused.headers
    assert {
        "event": "security.rate_limited",
        "action": "login",
        "scope": "email",
        "log_level": "warning",
    } in records


async def test_successful_logins_count_towards_the_email_limit(client: httpx.AsyncClient) -> None:
    await _account()

    statuses = [(await _login(client)).status_code for _ in range(11)]

    assert statuses == [204] * 10 + [429]


async def test_thirty_first_attempt_from_one_ip_is_429(app: FastAPI) -> None:
    await _account()
    async with _client_from(app, "203.0.113.7") as busy, _client_from(app, "198.51.100.1") as other:
        statuses = [
            (await _login(busy, email=f"cook{index}@example.org")).status_code
            for index in range(30)
        ]
        refused = await _login(busy)
        elsewhere = await _login(other)

    assert statuses == [401] * 30
    assert refused.status_code == 429
    assert 1 <= int(refused.headers["retry-after"]) <= 900
    assert elsewhere.status_code == 204


async def test_passwords_of_invalid_format_do_not_spend_the_limits(
    client: httpx.AsyncClient,
) -> None:
    await _account()

    rejected = [(await _login(client, password="short")).status_code for _ in range(12)]
    accepted = await _login(client)

    assert set(rejected) == {401}
    assert accepted.status_code == 204


async def test_limit_keys_hide_the_email(client: httpx.AsyncClient) -> None:
    await _account()

    await _login(client)

    keys = sorted(await get_redis().keys("rate_limit:*"))
    secret = get_settings().security.secret_key.get_secret_value().encode()
    assert keys == [
        "rate_limit:login_email:" + email_fingerprint("anna@example.org", secret),
        "rate_limit:login_ip:127.0.0.1",
    ]


async def test_limiter_outage_is_503_without_a_session(
    app: FastAPI, client: httpx.AsyncClient, dead_redis: Redis
) -> None:
    await _account()
    app.dependency_overrides[get_rate_limiter] = lambda: RedisRateLimiter(
        client=dead_redis, operation_timeout_seconds=0.5
    )

    response = await _login(client)

    assert response.status_code == 503
    assert response.headers["content-type"] == PROBLEM_JSON
    assert "set-cookie" not in response.headers


async def test_session_store_outage_is_503_without_a_cookie(
    app: FastAPI, client: httpx.AsyncClient, dead_redis: Redis
) -> None:
    await _account()
    app.dependency_overrides[get_session_store] = lambda: _dead_session_store(dead_redis)

    response = await _login(client)

    assert response.status_code == 503
    assert "set-cookie" not in response.headers


@pytest.mark.parametrize(
    ("content", "content_type"),
    [
        (json.dumps(BODY), "text/plain"),
        (json.dumps(BODY | {"remember": True}), "application/json"),
        (json.dumps(BODY | {"email": "not-an-email"}), "application/json"),
        (json.dumps({"email": "anna@example.org"}), "application/json"),
    ],
    ids=["text_plain", "unknown_field", "bad_email", "missing_password"],
)
async def test_malformed_request_is_422_and_spends_no_limit(
    client: httpx.AsyncClient, content: str, content_type: str
) -> None:
    await _account()

    response = await client.post(LOGIN, content=content, headers={"Content-Type": content_type})

    assert response.status_code == 422
    assert response.json()["type"] == "/problems/validation-error"
    assert await get_redis().keys("rate_limit:*") == []


async def test_login_is_post_only(client: httpx.AsyncClient) -> None:
    response = await client.get(LOGIN)

    assert response.status_code == 405


async def test_login_and_logout_are_security_events(client: httpx.AsyncClient) -> None:
    user_id = await _account()

    with structlog.testing.capture_logs() as records:
        token = _token(await _login(client))
        await client.post(LOGOUT, headers=_with(token))
        await _login(client, password="wrong horse battery")

    events = [record for record in records if record["event"].startswith("security.")]
    assert events == [
        {
            "event": "security.login_succeeded",
            "user_id": str(user_id),
            "method": "password",
            "log_level": "info",
        },
        {"event": "security.logout", "user_id": str(user_id), "log_level": "info"},
        {
            "event": "security.login_failed",
            "user_id": str(user_id),
            "reason": "bad_credentials",
            "log_level": "info",
        },
    ]


async def test_credentials_and_tokens_never_reach_the_logs(
    client: httpx.AsyncClient, caplog: pytest.LogCaptureFixture
) -> None:
    await _account()
    caplog.set_level(logging.DEBUG)

    with structlog.testing.capture_logs() as records:
        first = _token(await _login(client))
        second = _token(await client.post(LOGIN, json=BODY, headers=_with(first)))
        await _login(client, password="wrong horse battery")
        await _login(client, email="nobody@example.org")
        await client.post(LOGOUT, headers=_with(second))

    everything = (repr(records) + caplog.text).lower()
    assert "anna" not in everything
    assert "nobody" not in everything
    assert "horse" not in everything
    assert first.lower() not in everything
    assert second.lower() not in everything


async def test_parallel_logins_all_get_their_own_session(client: httpx.AsyncClient) -> None:
    await _account()

    responses = await asyncio.gather(*(_login(client) for _ in range(6)))

    assert [response.status_code for response in responses] == [204] * 6
    tokens = {_token(response) for response in responses}
    assert len(tokens) == 6


async def test_concurrent_logins_share_four_hashing_slots(
    client: httpx.AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    await _account()
    active = 0
    peak = 0
    lock = threading.Lock()
    real = argon2.PasswordHasher.verify

    def slow_verify(
        hasher: argon2.PasswordHasher, password_hash: str | bytes, password: str | bytes
    ) -> bool:
        nonlocal active, peak
        with lock:
            active += 1
            peak = max(peak, active)
        try:
            time.sleep(0.05)
            return real(hasher, password_hash, password)
        finally:
            with lock:
                active -= 1

    monkeypatch.setattr(argon2.PasswordHasher, "verify", slow_verify)

    responses = await asyncio.gather(*(_login(client) for _ in range(10)))

    assert [response.status_code for response in responses] == [204] * 10
    assert peak == 4


@pytest.fixture
def services(app: FastAPI) -> tuple[list[PasswordLoginService], list[PasswordHasher]]:
    built: list[PasswordLoginService] = []
    hashers: list[PasswordHasher] = []

    def recording(
        uow: Annotated[UnitOfWork, Depends(get_uow)],
        limiter: Annotated[RateLimiter, Depends(get_rate_limiter)],
        hasher: Annotated[PasswordHasher, Depends(get_password_hasher)],
        sessions: Annotated[SessionStore, Depends(get_session_store)],
        events: Annotated[SecurityEvents, Depends(get_security_events)],
        secret: Annotated[bytes, Depends(get_secret)],
    ) -> PasswordLoginService:
        service = get_password_login_service(uow, limiter, hasher, sessions, events, secret)
        built.append(service)
        hashers.append(hasher)
        return service

    app.dependency_overrides[get_password_login_service] = recording
    return built, hashers


async def test_each_login_gets_its_own_service_and_the_shared_hasher(
    client: httpx.AsyncClient,
    services: tuple[list[PasswordLoginService], list[PasswordHasher]],
) -> None:
    await _account()

    await _login(client)
    await _login(client, password="wrong horse battery")

    built, hashers = services
    assert len(built) == 2
    assert built[0] is not built[1]
    assert hashers[0] is hashers[1]


async def test_parallel_logins_use_the_hasher_of_the_application(
    app: FastAPI,
    client: httpx.AsyncClient,
    services: tuple[list[PasswordLoginService], list[PasswordHasher]],
) -> None:
    await _account()

    await asyncio.gather(*(_login(client, password="wrong horse battery") for _ in range(8)))

    _, hashers = services
    assert hashers == [app.state.password_hasher] * 8


def test_openapi_documents_login(app: FastAPI) -> None:
    operation = app.openapi()["paths"][LOGIN]["post"]

    assert operation["summary"]
    assert {"204", "401", "403", "422", "429", "503"} <= set(operation["responses"])
    schema_ref = operation["requestBody"]["content"]["application/json"]["schema"]["$ref"]
    schema = app.openapi()["components"]["schemas"][schema_ref.rsplit("/", 1)[1]]
    assert schema["required"] == ["email", "password"]
    assert schema["additionalProperties"] is False
    assert schema["properties"]["email"]["format"] == "email"
