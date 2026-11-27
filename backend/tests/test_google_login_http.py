import asyncio
import json
import logging
import time
import uuid
from collections.abc import AsyncIterator
from dataclasses import replace
from datetime import timedelta
from hashlib import sha256
from http.cookiejar import CookieJar, DefaultCookiePolicy
from http.cookies import Morsel, SimpleCookie
from typing import Any
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest
import structlog
from fakes import FakeLimiter, FakeOidcProvider
from fastapi import FastAPI
from redis.asyncio import Redis
from sqlalchemy import select

from app.core.config import get_settings
from app.core.db import get_session_factory
from app.core.redis import get_redis
from app.modules.identity.domain.enums import IdentityProvider, TokenPurpose
from app.modules.identity.infrastructure.exceptions import IdentityProviderUnavailableError
from app.modules.identity.infrastructure.models import User, UserIdentity
from app.modules.identity.infrastructure.redis_login_state_store import RedisLoginStateStore
from app.modules.identity.infrastructure.redis_one_time_token_store import RedisOneTimeTokenStore
from app.modules.identity.routes.dependencies import (
    get_login_state_store,
    get_oidc_provider,
    get_one_time_token_store,
    get_rate_limiter,
)
from app.modules.identity.service.dto import OidcIdentityDTO, ProviderRejectionDTO

LOGIN = "/api/v1/auth/google/login"
CALLBACK = "/api/v1/auth/google/callback"
NOT_ME = "/api/v1/auth/google/not-me"
ME = "/api/v1/users/me"
BINDING = "oauth_binding"
PROBLEM_JSON = "application/problem+json"


def _client_from(app: FastAPI, ip: str = "127.0.0.1") -> httpx.AsyncClient:
    transport = httpx.ASGITransport(app, raise_app_exceptions=False, client=(ip, 5000))
    jar = CookieJar(policy=DefaultCookiePolicy(allowed_domains=[]))
    return httpx.AsyncClient(transport=transport, base_url="http://test", cookies=jar)


@pytest.fixture
async def client(app: FastAPI) -> AsyncIterator[httpx.AsyncClient]:
    async with _client_from(app) as instance:
        yield instance


@pytest.fixture
def google(app: FastAPI) -> FakeOidcProvider:
    provider = FakeOidcProvider(
        OidcIdentityDTO(
            subject="sub-anna",
            email="anna@example.org",
            email_verified=True,
            name="Anna Google",
            picture="https://google/anna.png",
            nonce="",
        )
    )
    app.dependency_overrides[get_oidc_provider] = lambda: provider
    return provider


def _cookies(response: httpx.Response) -> dict[str, Morsel[str]]:
    found: dict[str, Morsel[str]] = {}
    for header in response.headers.get_list("set-cookie"):
        jar: SimpleCookie = SimpleCookie()
        jar.load(header)
        found.update(jar)
    return found


def _session_cookie_name() -> str:
    return get_settings().session.cookie_name


def _cookie_header(**values: str) -> dict[str, str]:
    return {"Cookie": "; ".join(f"{name}={value}" for name, value in values.items())}


class Started:
    def __init__(self, response: httpx.Response) -> None:
        self.response = response
        self.state = parse_qs(urlsplit(response.headers["location"]).query)["state"][0]
        self.binding = _cookies(response)[BINDING].value


async def _start(client: httpx.AsyncClient, next_path: str | None = None) -> Started:
    params = {"next": next_path} if next_path is not None else {}
    response = await client.get(LOGIN, params=params)
    assert response.status_code == 302
    return Started(response)


async def _callback(
    client: httpx.AsyncClient,
    google: FakeOidcProvider,
    started: Started,
    session: str | None = None,
    binding: str | None = None,
    **answer: Any,
) -> httpx.Response:
    if isinstance(google.answer, OidcIdentityDTO):
        google.answer = replace(google.answer, nonce=google.authorized[-1][1], **answer)
    cookies = {BINDING: binding or started.binding}
    if session is not None:
        cookies[_session_cookie_name()] = session
    return await client.get(
        CALLBACK,
        params={"code": "4/code-from-google", "state": started.state},
        headers=_cookie_header(**cookies),
    )


async def _google_session(
    client: httpx.AsyncClient, google: FakeOidcProvider, **answer: Any
) -> str:
    response = await _callback(client, google, await _start(client), **answer)
    assert response.status_code == 303
    return _cookies(response)[_session_cookie_name()].value


async def _me(client: httpx.AsyncClient, session: str) -> int:
    response = await client.get(ME, headers=_cookie_header(**{_session_cookie_name(): session}))
    return response.status_code


def _login_error(response: httpx.Response) -> str:
    assert response.status_code == 303
    location = urlsplit(response.headers["location"])
    assert location.path == "/login"
    [error] = parse_qs(location.query)["error"]
    assert "_" not in error
    return error


def _assert_binding_dropped(response: httpx.Response) -> None:
    binding = _cookies(response)[BINDING]
    assert binding.value == ""
    assert binding["max-age"] == "0"
    assert binding["path"] == "/api/v1/auth/google"


async def _stored_user(email: str = "anna@example.org") -> User | None:
    async with get_session_factory()() as session:
        user: User | None = await session.scalar(select(User).where(User.email == email))
        return user


async def _identities() -> list[tuple[uuid.UUID, str]]:
    async with get_session_factory()() as session:
        rows = await session.execute(select(UserIdentity.user_id, UserIdentity.subject))
        return [(row.user_id, row.subject) for row in rows]


async def test_login_sends_the_browser_to_google_with_a_binding_cookie(
    client: httpx.AsyncClient, google: FakeOidcProvider
) -> None:
    response = await client.get(LOGIN)

    assert response.status_code == 302
    assert response.headers["location"].startswith("https://accounts.example/auth?state=")
    assert response.headers["cache-control"] == "no-store"
    binding = _cookies(response)[BINDING]
    assert len(binding.value) == 43
    assert binding["httponly"] is True
    assert binding["samesite"] == "lax"
    assert binding["path"] == "/api/v1/auth/google"
    assert binding["max-age"] == "600"
    assert not binding["secure"]


async def test_login_cookie_is_secure_when_sessions_are(
    app: FastAPI, client: httpx.AsyncClient, google: FakeOidcProvider
) -> None:
    base = get_settings()
    settings = base.model_copy(
        update={"session": base.session.model_copy(update={"cookie_secure": True})}
    )
    app.dependency_overrides[get_settings] = lambda: settings

    response = await client.get(LOGIN)

    assert _cookies(response)[BINDING]["secure"] is True


async def test_login_keeps_the_pending_state_in_redis_for_ten_minutes(
    client: httpx.AsyncClient, google: FakeOidcProvider
) -> None:
    started = await _start(client)

    key = "oauth_state:" + sha256(started.state.encode()).hexdigest()
    assert 590 <= await get_redis().ttl(key) <= 600
    raw = await get_redis().get(key)
    assert isinstance(raw, str)
    assert started.binding not in raw
    assert json.loads(raw)["browser_binding_hash"] == sha256(started.binding.encode()).hexdigest()


async def test_first_google_login_creates_the_account_and_signs_in(
    client: httpx.AsyncClient, google: FakeOidcProvider
) -> None:
    started = await _start(client, "/recipes/7")

    response = await _callback(client, google, started)

    assert response.status_code == 303
    assert response.headers["location"] == "/recipes/7"
    assert response.headers["cache-control"] == "no-store"
    session = _cookies(response)[_session_cookie_name()]
    assert session["httponly"] is True
    assert session["path"] == "/"
    assert await _me(client, session.value) == 200
    _assert_binding_dropped(response)
    user = await _stored_user()
    assert user is not None
    assert user.email_verified_at is not None
    assert user.display_name == "Anna Google"
    assert await _identities() == [(user.id, "sub-anna")]
    assert google.exchanged[-1][0] == "4/code-from-google"


@pytest.mark.parametrize("next_path", ["//evil.example", "https://evil.example/x", ""])
async def test_foreign_next_lands_on_the_home_page(
    client: httpx.AsyncClient, google: FakeOidcProvider, next_path: str
) -> None:
    response = await _callback(client, google, await _start(client, next_path))

    assert response.headers["location"] == "/"


async def test_second_login_finds_the_same_account(
    client: httpx.AsyncClient, google: FakeOidcProvider
) -> None:
    await _google_session(client, google)
    await _google_session(client, google)

    user = await _stored_user()
    assert user is not None
    assert await _identities() == [(user.id, "sub-anna")]


async def test_google_login_replaces_the_session_of_this_browser(
    client: httpx.AsyncClient, google: FakeOidcProvider
) -> None:
    old = await _google_session(client, google)

    response = await _callback(client, google, await _start(client), session=old)

    new = _cookies(response)[_session_cookie_name()].value
    assert new != old
    assert await _me(client, old) == 401
    assert await _me(client, new) == 200


async def test_callback_without_the_binding_cookie_is_refused(
    client: httpx.AsyncClient, google: FakeOidcProvider
) -> None:
    started = await _start(client)

    response = await client.get(CALLBACK, params={"code": "4/c", "state": started.state})

    assert _login_error(response) == "state"
    assert response.headers["cache-control"] == "no-store"
    assert _session_cookie_name() not in _cookies(response)
    _assert_binding_dropped(response)
    assert google.exchanged == []


async def test_callback_with_a_binding_of_another_browser_is_refused(
    client: httpx.AsyncClient, google: FakeOidcProvider
) -> None:
    victim = await _start(client)
    attacker = await _start(client)

    response = await _callback(client, google, victim, binding=attacker.binding)

    assert _login_error(response) == "state"
    assert await _stored_user() is None


async def test_callback_works_only_once(
    client: httpx.AsyncClient, google: FakeOidcProvider
) -> None:
    started = await _start(client)
    await _callback(client, google, started)

    again = await _callback(client, google, started)

    assert _login_error(again) == "state"


async def test_cancel_on_the_google_page_is_cancelled(
    client: httpx.AsyncClient, google: FakeOidcProvider
) -> None:
    started = await _start(client)

    response = await client.get(
        CALLBACK,
        params={"error": "access_denied", "state": started.state},
        headers=_cookie_header(**{BINDING: started.binding}),
    )

    assert _login_error(response) == "cancelled"
    _assert_binding_dropped(response)
    assert google.exchanged == []


@pytest.mark.parametrize(
    ("params", "error"),
    [
        ({"error": "server_error", "state": "S" * 43}, "provider"),
        ({"error": "access_denied", "code": "4/c", "state": "S" * 43}, "cancelled"),
        ({"error": "", "code": "4/c", "state": "S" * 43}, "provider"),
        ({"state": "S" * 43}, "state"),
        ({"code": "4/c"}, "state"),
        ({}, "state"),
    ],
    ids=["google_error", "denied_with_code", "empty_error", "no_code", "no_state", "nothing"],
)
async def test_incomplete_callback_never_reaches_google(
    client: httpx.AsyncClient, google: FakeOidcProvider, params: dict[str, str], error: str
) -> None:
    response = await client.get(CALLBACK, params=params)

    assert _login_error(response) == error
    _assert_binding_dropped(response)
    assert google.exchanged == []


async def test_rejection_by_google_is_provider(
    client: httpx.AsyncClient, google: FakeOidcProvider
) -> None:
    started = await _start(client)
    google.answer = ProviderRejectionDTO("invalid_grant")

    response = await _callback(client, google, started)

    assert _login_error(response) == "provider"


async def test_unverified_google_email_is_refused(
    client: httpx.AsyncClient, google: FakeOidcProvider
) -> None:
    response = await _callback(client, google, await _start(client), email_verified=False)

    assert _login_error(response) == "email-unverified"


async def test_new_google_email_taken_by_another_account_is_a_conflict(
    client: httpx.AsyncClient, google: FakeOidcProvider
) -> None:
    await _google_session(client, google)
    async with get_session_factory()() as session:
        session.add(User(email="boris@example.org", display_name="Boris", avatar_url=None))
        await session.commit()

    response = await _callback(client, google, await _start(client), email="Boris@example.org")

    assert _login_error(response) == "email-conflict"
    assert _session_cookie_name() not in _cookies(response)
    assert await _stored_user() is not None


async def test_google_outage_is_unavailable_and_logged_as_an_error(
    client: httpx.AsyncClient, google: FakeOidcProvider
) -> None:
    started = await _start(client)
    google.failure = IdentityProviderUnavailableError("Google token endpoint answered 401 x")

    with structlog.testing.capture_logs() as records:
        response = await _callback(client, google, started)

    assert _login_error(response) == "unavailable"
    _assert_binding_dropped(response)
    [record] = [r for r in records if r["event"] == "auth.google_callback_unavailable"]
    assert record["log_level"] == "error"
    assert isinstance(record["exc_info"], IdentityProviderUnavailableError)


async def test_state_store_outage_at_login_is_unavailable_and_logged(
    app: FastAPI, client: httpx.AsyncClient, google: FakeOidcProvider, dead_redis: Redis
) -> None:
    app.dependency_overrides[get_login_state_store] = lambda: RedisLoginStateStore(
        client=dead_redis, operation_timeout_seconds=0.5
    )

    with structlog.testing.capture_logs() as records:
        response = await client.get(LOGIN)

    assert _login_error(response) == "unavailable"
    assert response.headers["cache-control"] == "no-store"
    assert BINDING not in _cookies(response)
    [record] = [r for r in records if r["event"] == "auth.google_login_unavailable"]
    assert record["log_level"] == "error"


@pytest.fixture
async def silent_redis() -> AsyncIterator[Redis]:
    writers: list[asyncio.StreamWriter] = []

    async def swallow(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        writers.append(writer)
        await reader.read()

    server = await asyncio.start_server(swallow, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    client = Redis(host="127.0.0.1", port=port, socket_connect_timeout=30, socket_timeout=30)

    yield client

    await client.aclose()
    for writer in writers:
        writer.close()
    server.close()
    await server.wait_closed()


async def test_state_store_waits_only_as_long_as_the_settings_say(
    app: FastAPI, client: httpx.AsyncClient, google: FakeOidcProvider, silent_redis: Redis
) -> None:
    base = get_settings()
    settings = base.model_copy(
        update={
            "login_state": base.login_state.model_copy(update={"operation_timeout_seconds": 0.3})
        }
    )
    app.dependency_overrides[get_settings] = lambda: settings
    app.dependency_overrides[get_redis] = lambda: silent_redis
    app.dependency_overrides[get_rate_limiter] = lambda: FakeLimiter()
    started = time.monotonic()

    async with asyncio.timeout(5):
        response = await client.get(LOGIN)

    assert _login_error(response) == "unavailable"
    assert time.monotonic() - started < 1.5


async def test_twenty_first_login_start_from_one_ip_is_rate_limited(
    app: FastAPI, google: FakeOidcProvider
) -> None:
    async with _client_from(app, ip="198.51.100.1") as client:
        for _ in range(20):
            assert (await client.get(LOGIN)).status_code == 302

        response = await client.get(LOGIN)

        assert _login_error(response) == "rate-limited"
        assert BINDING not in _cookies(response)
        callback = await client.get(CALLBACK, params={"code": "4/c", "state": "S" * 43})
        assert _login_error(callback) == "state"

    async with _client_from(app, ip="198.51.100.2") as other:
        assert (await other.get(LOGIN)).status_code == 302


async def test_twenty_first_callback_from_one_ip_is_rate_limited(
    app: FastAPI, google: FakeOidcProvider
) -> None:
    async with _client_from(app, ip="198.51.100.3") as client:
        for _ in range(20):
            response = await client.get(CALLBACK, params={"code": "4/c", "state": "S" * 43})
            assert _login_error(response) == "state"

        limited = await client.get(CALLBACK, params={"code": "4/c", "state": "S" * 43})

        assert _login_error(limited) == "rate-limited"
        assert (await client.get(LOGIN)).status_code == 302

    async with _client_from(app, ip="198.51.100.4") as other:
        response = await other.get(CALLBACK, params={"code": "4/c", "state": "S" * 43})
        assert _login_error(response) == "state"


async def _not_me_token(user_id: uuid.UUID) -> str:
    store = RedisOneTimeTokenStore(client=get_redis(), operation_timeout_seconds=1.0)
    return await store.issue(TokenPurpose.GOOGLE_NOT_ME, user_id, 0, timedelta(days=7))


async def _post_not_me(client: httpx.AsyncClient, body: dict[str, Any]) -> httpx.Response:
    return await client.post(
        NOT_ME, content=json.dumps(body), headers={"Content-Type": "application/json"}
    )


async def test_not_me_unlinks_google_and_signs_out_everywhere(
    client: httpx.AsyncClient, google: FakeOidcProvider
) -> None:
    session = await _google_session(client, google)
    user = await _stored_user()
    assert user is not None

    response = await _post_not_me(client, {"token": await _not_me_token(user.id)})

    assert response.status_code == 204
    assert response.headers["cache-control"] == "no-store"
    assert await _identities() == []
    assert await _me(client, session) == 401


async def test_not_me_link_works_once(client: httpx.AsyncClient, google: FakeOidcProvider) -> None:
    await _google_session(client, google)
    user = await _stored_user()
    assert user is not None
    token = await _not_me_token(user.id)
    await _post_not_me(client, {"token": token})

    again = await _post_not_me(client, {"token": token})

    assert again.status_code == 422
    assert again.headers["content-type"] == PROBLEM_JSON
    assert again.json()["type"] == "/problems/token-invalid"


async def test_password_reset_token_does_not_work_for_not_me(
    client: httpx.AsyncClient, google: FakeOidcProvider
) -> None:
    await _google_session(client, google)
    user = await _stored_user()
    assert user is not None
    store = RedisOneTimeTokenStore(client=get_redis(), operation_timeout_seconds=1.0)
    token = await store.issue(TokenPurpose.PASSWORD_RESET, user.id, 0, timedelta(hours=1))

    response = await _post_not_me(client, {"token": token})

    assert response.status_code == 422
    assert await _identities() != []


@pytest.mark.parametrize(
    "body",
    [{}, {"token": 42}, {"token": "A" * 43, "extra": True}],
    ids=["empty", "not_a_string", "extra_field"],
)
async def test_malformed_not_me_is_a_validation_error(
    client: httpx.AsyncClient, body: dict[str, Any]
) -> None:
    response = await _post_not_me(client, body)

    assert response.status_code == 422
    assert response.json()["type"] == "/problems/validation-error"


async def test_not_me_with_token_store_down_is_503(
    app: FastAPI, client: httpx.AsyncClient, dead_redis: Redis
) -> None:
    app.dependency_overrides[get_one_time_token_store] = lambda: RedisOneTimeTokenStore(
        client=dead_redis, operation_timeout_seconds=0.5
    )

    response = await _post_not_me(client, {"token": "A" * 43})

    assert response.status_code == 503
    assert response.headers["content-type"] == PROBLEM_JSON


async def test_secrets_never_reach_the_logs(
    client: httpx.AsyncClient, google: FakeOidcProvider, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.DEBUG)

    with structlog.testing.capture_logs() as records:
        started = await _start(client)
        response = await _callback(client, google, started)
        session = _cookies(response)[_session_cookie_name()].value
        user = await _stored_user()
        assert user is not None
        token = await _not_me_token(user.id)
        await _post_not_me(client, {"token": token})

    app_logs = [record.getMessage() for record in caplog.records if record.name != "httpx"]
    everything = repr(records) + "\n".join(app_logs)
    for secret in (started.state, started.binding, "4/code-from-google", session, token):
        assert secret not in everything
    assert "anna@" not in everything.lower()
    events = {record["event"] for record in records}
    assert {"security.login_succeeded", "security.google_disowned"} <= events


def test_openapi_documents_the_google_endpoints(app: FastAPI) -> None:
    paths = app.openapi()["paths"]

    assert {"302", "303"} <= set(paths[LOGIN]["get"]["responses"])
    assert "303" in paths[CALLBACK]["get"]["responses"]
    assert {"204", "422", "503"} <= set(paths[NOT_ME]["post"]["responses"])
    assert [p["name"] for p in paths[LOGIN]["get"]["parameters"]] == ["next"]
    login_errors = paths[LOGIN]["get"]["responses"]["303"]["description"]
    callback_errors = paths[CALLBACK]["get"]["responses"]["303"]["description"]
    assert "rate-limited" in login_errors
    for code in ("email-unverified", "email-conflict", "rate-limited", "cancelled"):
        assert code in callback_errors
    assert "_" not in login_errors + callback_errors
    for path, method in ((LOGIN, "get"), (CALLBACK, "get"), (NOT_ME, "post")):
        assert paths[path][method]["summary"]


async def test_identity_provider_is_stored_as_google(
    client: httpx.AsyncClient, google: FakeOidcProvider
) -> None:
    await _google_session(client, google)

    async with get_session_factory()() as session:
        providers = list(await session.scalars(select(UserIdentity.provider)))
    assert providers == [IdentityProvider.GOOGLE]
