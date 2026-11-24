import asyncio
import json
import logging
import time
import uuid
from collections import Counter
from collections.abc import Callable, Iterator
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from http.cookies import SimpleCookie
from typing import Annotated, Any

import httpx
import pytest
import structlog
from fastapi import Depends, FastAPI
from redis.asyncio import Redis
from sqlalchemy import text
from sqlalchemy.pool import QueuePool
from structlog.processors import JSONRenderer

from app.core.config import get_settings
from app.core.db import get_engine, get_session_factory
from app.core.redis import get_redis
from app.modules.identity.domain.enums import WorkspaceRole
from app.modules.identity.infrastructure.models import Membership, User, Workspace
from app.modules.identity.infrastructure.redis_rate_limiter import RedisRateLimiter
from app.modules.identity.infrastructure.redis_session_store import RedisSessionStore
from app.modules.identity.routes.dependencies import (
    get_current_user,
    get_rate_limiter,
    get_session_store,
    require_nickname,
)
from app.modules.identity.service.dto import SessionDTO, UserDTO

ME = "/api/v1/users/me"
LOGOUT = "/api/v1/auth/logout"
AVAILABILITY = "/api/v1/nicknames/availability"
GATED = "/gated"
PROBLEM_JSON = "application/problem+json"
AVATAR = "https://lh3.googleusercontent.com/a/ACg8ocK-avatar=s96-c"


def _now() -> datetime:
    return datetime.now(UTC)


def _store(client: Redis, now: Callable[[], datetime] = _now) -> RedisSessionStore:
    session = get_settings().session
    return RedisSessionStore(
        client=client,
        idle_ttl_seconds=session.idle_ttl_seconds,
        absolute_ttl_seconds=session.absolute_ttl_seconds,
        operation_timeout_seconds=session.operation_timeout_seconds,
        now=now,
    )


def _cookie(token: str) -> dict[str, str]:
    return {"Cookie": f"{get_settings().session.cookie_name}={token}"}


def _session_key(token: str) -> str:
    return "session:" + sha256(token.encode()).hexdigest()


def _checked_out() -> int:
    pool = get_engine().pool
    assert isinstance(pool, QueuePool)
    return pool.checkedout()


class CountingStore:
    def __init__(self, inner: RedisSessionStore) -> None:
        self._inner = inner
        self.resolves = 0

    async def create(self, user_id: uuid.UUID, credentials_version: int) -> str:
        return await self._inner.create(user_id, credentials_version)

    async def resolve(self, token: str) -> SessionDTO | None:
        self.resolves += 1
        return await self._inner.resolve(token)

    async def revoke(self, token: str) -> None:
        await self._inner.revoke(token)


async def _user(**overrides: Any) -> User:
    suffix = uuid.uuid4().hex[:8]
    values: dict[str, Any] = {
        "email": f"cook-{suffix}@example.com",
        "display_name": f"Cook {suffix}",
        "avatar_url": None,
    }
    async with get_session_factory()() as session:
        user = User(**(values | overrides))
        session.add(user)
        await session.commit()
        return user


async def _join(user: User, role: WorkspaceRole, name: str = "Sunday dinners") -> Workspace:
    async with get_session_factory()() as session:
        workspace = Workspace(name=name, owner_id=user.id)
        session.add(workspace)
        await session.flush()
        session.add(Membership(user_id=user.id, workspace_id=workspace.id, role=role))
        await session.commit()
        return workspace


async def _signed_in(user: User) -> str:
    return await _store(get_redis()).create(user.id, user.credentials_version)


async def test_missing_cookie_is_401_problem(client: httpx.AsyncClient) -> None:
    response = await client.get(ME)
    body = response.json()

    assert response.status_code == 401
    assert response.headers["content-type"] == PROBLEM_JSON
    assert response.headers["www-authenticate"] == "Cookie"
    assert body["type"] == "about:blank"
    assert body["title"] == "Unauthorized"
    assert body["request_id"] == response.headers["x-request-id"]


@pytest.mark.parametrize(
    "token",
    ["", "A" * 42, "A" * 44, "A" * 42 + "!"],
    ids=["empty", "short", "long", "bang"],
)
async def test_malformed_cookie_is_401(client: httpx.AsyncClient, token: str) -> None:
    response = await client.get(ME, headers=_cookie(token))

    assert response.status_code == 401


async def test_unknown_token_is_401(client: httpx.AsyncClient) -> None:
    response = await client.get(ME, headers=_cookie("A" * 43))

    assert response.status_code == 401


async def test_malformed_cookie_is_401_even_when_redis_is_down(
    app: FastAPI, client: httpx.AsyncClient, dead_redis: Redis
) -> None:
    app.dependency_overrides[get_session_store] = lambda: _store(dead_redis)

    response = await client.get(ME, headers=_cookie("A" * 42 + "!"))

    assert response.status_code == 401


async def test_me_without_workspace(client: httpx.AsyncClient) -> None:
    user = await _user()
    token = await _signed_in(user)

    response = await client.get(ME, headers=_cookie(token))

    assert response.status_code == 200
    assert response.json() == {
        "id": str(user.id),
        "email": user.email,
        "display_name": user.display_name,
        "nickname": None,
        "avatar_url": None,
        "workspace": None,
    }


@pytest.mark.parametrize("role", list(WorkspaceRole))
async def test_me_with_workspace(client: httpx.AsyncClient, role: WorkspaceRole) -> None:
    user = await _user()
    workspace = await _join(user, role, name="Sunday dinners")
    token = await _signed_in(user)

    response = await client.get(ME, headers=_cookie(token))

    assert response.status_code == 200
    assert response.json()["workspace"] == {
        "id": str(workspace.id),
        "name": "Sunday dinners",
        "role": role.value,
    }


async def test_me_returns_google_avatar_as_is(client: httpx.AsyncClient) -> None:
    user = await _user(avatar_url=AVATAR)
    token = await _signed_in(user)

    response = await client.get(ME, headers=_cookie(token))

    assert response.status_code == 200
    assert response.json()["avatar_url"] == AVATAR


async def test_me_is_not_cacheable(client: httpx.AsyncClient) -> None:
    token = await _signed_in(await _user())

    response = await client.get(ME, headers=_cookie(token))

    assert response.headers["cache-control"] == "no-store"


async def test_revoked_session_is_401(client: httpx.AsyncClient) -> None:
    token = await _signed_in(await _user())
    await _store(get_redis()).revoke(token)

    response = await client.get(ME, headers=_cookie(token))

    assert response.status_code == 401


async def test_session_past_absolute_lifetime_is_401(client: httpx.AsyncClient) -> None:
    user = await _user()
    absolute = get_settings().session.absolute_ttl_seconds
    long_ago = _now() - timedelta(seconds=absolute + 60)
    token = await _store(get_redis(), now=lambda: long_ago).create(user.id, 0)

    response = await client.get(ME, headers=_cookie(token))

    assert response.status_code == 401


async def test_session_of_deleted_user_is_401_and_forgotten(client: httpx.AsyncClient) -> None:
    user = await _user()
    token = await _signed_in(user)
    async with get_engine().begin() as connection:
        await connection.execute(text("DELETE FROM users WHERE id = :id"), {"id": user.id})

    response = await client.get(ME, headers=_cookie(token))

    assert response.status_code == 401
    assert await get_redis().exists(_session_key(token)) == 0


async def test_valid_cookie_with_redis_down_is_503(
    app: FastAPI, client: httpx.AsyncClient, dead_redis: Redis
) -> None:
    app.dependency_overrides[get_session_store] = lambda: _store(dead_redis)
    started = time.monotonic()

    response = await client.get(ME, headers=_cookie("A" * 43))

    assert time.monotonic() - started < 3
    assert response.status_code == 503
    assert response.headers["content-type"] == PROBLEM_JSON
    assert "www-authenticate" not in response.headers


async def test_session_is_resolved_once_per_request(
    app: FastAPI, client: httpx.AsyncClient
) -> None:
    counting = CountingStore(_store(get_redis()))
    app.dependency_overrides[get_session_store] = lambda: counting
    token = await _signed_in(await _user())

    await client.get(ME, headers=_cookie(token))

    assert counting.resolves == 1


async def test_connections_return_to_pool(client: httpx.AsyncClient) -> None:
    member = await _user()
    await _join(member, WorkspaceRole.OWNER)
    member_token = await _signed_in(member)
    orphan = await _user()
    orphan_token = await _signed_in(orphan)
    async with get_engine().begin() as connection:
        await connection.execute(text("DELETE FROM users WHERE id = :id"), {"id": orphan.id})

    ok = await client.get(ME, headers=_cookie(member_token))
    after_ok = _checked_out()
    rejected = await client.get(ME, headers=_cookie(orphan_token))

    assert ok.status_code == 200
    assert after_ok == 0
    assert rejected.status_code == 401
    assert _checked_out() == 0


async def test_every_401_looks_the_same(client: httpx.AsyncClient) -> None:
    deleted = await _user()
    orphan_token = await _signed_in(deleted)
    async with get_engine().begin() as connection:
        await connection.execute(text("DELETE FROM users WHERE id = :id"), {"id": deleted.id})
    revoked_token = await _signed_in(await _user())
    await _store(get_redis()).revoke(revoked_token)

    responses = [
        await client.get(ME),
        await client.get(ME, headers=_cookie("garbage")),
        await client.get(ME, headers=_cookie("A" * 43)),
        await client.get(ME, headers=_cookie(revoked_token)),
        await client.get(ME, headers=_cookie(orphan_token)),
    ]

    bodies = [
        {key: value for key, value in response.json().items() if key not in {"request_id"}}
        for response in responses
    ]
    assert all(response.status_code == 401 for response in responses)
    assert all(body == bodies[0] for body in bodies)


async def test_endpoint_lives_only_under_versioned_prefix(client: httpx.AsyncClient) -> None:
    response = await client.get("/users/me")

    assert response.status_code == 404


def _deletion_cookie(response: httpx.Response) -> Any:
    headers = response.headers.get_list("set-cookie")
    assert len(headers) == 1
    jar: SimpleCookie = SimpleCookie()
    jar.load(headers[0])
    name = get_settings().session.cookie_name
    assert list(jar) == [name]
    return jar[name]


def _assert_deletes_session_cookie(response: httpx.Response, secure: bool) -> None:
    morsel = _deletion_cookie(response)
    assert morsel.value in {"", '""'}
    assert morsel["max-age"] == "0"
    assert morsel["path"] == "/"
    assert morsel["httponly"] is True
    assert morsel["samesite"].lower() == "lax"
    assert bool(morsel["secure"]) is secure
    assert morsel["domain"] == ""


async def test_logout_ends_the_session(client: httpx.AsyncClient) -> None:
    token = await _signed_in(await _user())

    response = await client.post(LOGOUT, headers=_cookie(token))

    assert response.status_code == 204
    assert response.content == b""
    assert await get_redis().exists(_session_key(token)) == 0


async def test_logout_deletes_the_cookie(client: httpx.AsyncClient) -> None:
    token = await _signed_in(await _user())

    response = await client.post(LOGOUT, headers=_cookie(token))

    _assert_deletes_session_cookie(response, secure=False)


@pytest.fixture
def secure_cookie(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    monkeypatch.setenv("SESSION__COOKIE_NAME", "__Host-session")
    monkeypatch.setenv("SESSION__COOKIE_SECURE", "true")
    get_settings.cache_clear()

    yield

    get_settings.cache_clear()


async def test_logout_deletes_a_secure_cookie_with_matching_attributes(
    client: httpx.AsyncClient, secure_cookie: None
) -> None:
    token = await _signed_in(await _user())

    response = await client.post(LOGOUT, headers=_cookie(token))

    assert response.status_code == 204
    _assert_deletes_session_cookie(response, secure=True)


async def test_old_cookie_is_useless_after_logout(client: httpx.AsyncClient) -> None:
    token = await _signed_in(await _user())
    await client.post(LOGOUT, headers=_cookie(token))

    response = await client.get(ME, headers=_cookie(token))

    assert response.status_code == 401


@pytest.mark.parametrize(
    "token", [None, "garbage", "A" * 43], ids=["no-cookie", "malformed", "unknown"]
)
async def test_logout_without_live_session_still_clears_cookie(
    client: httpx.AsyncClient, token: str | None
) -> None:
    response = await client.post(LOGOUT, headers=_cookie(token) if token else {})

    assert response.status_code == 204
    _assert_deletes_session_cookie(response, secure=False)


async def test_repeated_logout_is_harmless(client: httpx.AsyncClient) -> None:
    token = await _signed_in(await _user())
    await client.post(LOGOUT, headers=_cookie(token))

    response = await client.post(LOGOUT, headers=_cookie(token))

    assert response.status_code == 204


async def test_logout_with_redis_down_is_503_and_keeps_cookie(
    app: FastAPI, client: httpx.AsyncClient, dead_redis: Redis
) -> None:
    app.dependency_overrides[get_session_store] = lambda: _store(dead_redis)

    response = await client.post(LOGOUT, headers=_cookie("A" * 43))

    assert response.status_code == 503
    assert response.headers.get_list("set-cookie") == []


async def test_logout_is_post_only(client: httpx.AsyncClient) -> None:
    response = await client.get(LOGOUT)

    assert response.status_code == 405


def _access_records(records: list[Any]) -> list[Any]:
    return [record for record in records if record["event"] == "http.requested"]


async def test_access_log_names_the_authenticated_user(client: httpx.AsyncClient) -> None:
    user = await _user()
    token = await _signed_in(user)

    with structlog.testing.capture_logs() as records:
        await client.get(ME, headers=_cookie(token))

    [access] = _access_records(records)
    rendered = json.loads(JSONRenderer()(None, "", dict(access)))
    assert rendered["user_id"] == str(user.id)


@pytest.mark.parametrize("path", ["/healthz", ME], ids=["anonymous-probe", "rejected-me"])
async def test_access_log_has_no_user_for_anonymous_requests(
    client: httpx.AsyncClient, path: str
) -> None:
    with structlog.testing.capture_logs() as records:
        await client.get(path)

    [access] = _access_records(records)
    assert access.get("user_id") is None


async def test_every_request_still_gets_an_access_record(client: httpx.AsyncClient) -> None:
    with structlog.testing.capture_logs() as records:
        response = await client.get("/healthz")

    assert response.status_code == 200
    assert len(_access_records(records)) == 1


async def test_session_secrets_never_reach_the_logs(
    app: FastAPI,
    client: httpx.AsyncClient,
    dead_redis: Redis,
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.DEBUG)
    token = await _signed_in(await _user())

    with structlog.testing.capture_logs() as records:
        await client.get(ME, headers=_cookie(token))
        await client.post(LOGOUT, headers=_cookie(token))
        app.dependency_overrides[get_session_store] = lambda: _store(dead_redis)
        await client.get(ME, headers=_cookie(token))

    everything = repr(records) + caplog.text
    assert token not in everything
    assert sha256(token.encode()).hexdigest() not in everything


async def test_redis_outage_is_logged_once_with_cause_and_request_id(
    app: FastAPI, client: httpx.AsyncClient, dead_redis: Redis
) -> None:
    app.dependency_overrides[get_session_store] = lambda: _store(dead_redis)

    with structlog.testing.capture_logs(
        processors=[structlog.contextvars.merge_contextvars]
    ) as records:
        response = await client.get(ME, headers=_cookie("A" * 43))

    errors = [record for record in records if record["event"] == "app.request_error"]
    assert len(errors) == 1
    assert errors[0]["status_code"] == 503
    assert errors[0]["exc_info"].__cause__ is not None
    assert errors[0]["request_id"] == response.headers["x-request-id"]


async def _patch(client: httpx.AsyncClient, token: str, body: Any) -> httpx.Response:
    return await client.patch(ME, headers=_cookie(token), json=body)


async def _check(client: httpx.AsyncClient, token: str, nickname: str) -> httpx.Response:
    return await client.get(AVAILABILITY, params={"nickname": nickname}, headers=_cookie(token))


async def _stored_nickname(user_id: uuid.UUID) -> str | None:
    async with get_engine().connect() as connection:
        nickname: str | None = await connection.scalar(
            text("SELECT nickname FROM users WHERE id = :id"), {"id": user_id}
        )
    return nickname


async def _quarantine() -> dict[str, uuid.UUID | None]:
    async with get_engine().connect() as connection:
        rows = await connection.execute(
            text("SELECT nickname, released_by FROM released_nicknames")
        )
    return {row.nickname: row.released_by for row in rows}


async def _age_release(nickname: str, days: int) -> None:
    async with get_engine().begin() as connection:
        await connection.execute(
            text(
                "UPDATE released_nicknames SET released_at = now() - make_interval(days => :days) "
                "WHERE nickname = :nickname"
            ),
            {"days": days, "nickname": nickname},
        )


async def _delete_user(user_id: uuid.UUID) -> None:
    async with get_engine().begin() as connection:
        await connection.execute(text("DELETE FROM users WHERE id = :id"), {"id": user_id})


def _limiter_down(app: FastAPI, dead_redis: Redis) -> None:
    app.dependency_overrides[get_rate_limiter] = lambda: RedisRateLimiter(
        client=dead_redis, operation_timeout_seconds=0.5
    )


async def test_me_shows_the_nickname(client: httpx.AsyncClient) -> None:
    token = await _signed_in(await _user(nickname="anna"))

    response = await client.get(ME, headers=_cookie(token))

    assert response.json()["nickname"] == "anna"


async def test_first_nickname_is_set_in_normalized_form(client: httpx.AsyncClient) -> None:
    user = await _user()
    token = await _signed_in(user)

    response = await _patch(client, token, {"nickname": "  Anna.Cook "})

    assert response.status_code == 200
    assert response.json()["nickname"] == "anna.cook"
    assert response.json()["id"] == str(user.id)
    assert response.headers["cache-control"] == "no-store"
    assert await _stored_nickname(user.id) == "anna.cook"
    assert await _quarantine() == {}


async def test_patch_answers_with_the_whole_profile(client: httpx.AsyncClient) -> None:
    user = await _user()
    workspace = await _join(user, WorkspaceRole.OWNER, name="Sunday dinners")
    token = await _signed_in(user)

    patched = await _patch(client, token, {"nickname": "anna"})
    fetched = await client.get(ME, headers=_cookie(token))

    assert patched.json() == fetched.json()
    assert patched.json()["workspace"]["id"] == str(workspace.id)


@pytest.mark.parametrize("nickname", [None, "anna"], ids=["without_nickname", "with_nickname"])
async def test_empty_patch_changes_nothing(client: httpx.AsyncClient, nickname: str | None) -> None:
    user = await _user(nickname=nickname)
    token = await _signed_in(user)

    response = await _patch(client, token, {})

    assert response.status_code == 200
    assert response.json()["nickname"] == nickname
    assert await _stored_nickname(user.id) == nickname


async def test_merge_patch_media_type_is_accepted(client: httpx.AsyncClient) -> None:
    user = await _user()
    token = await _signed_in(user)

    response = await client.patch(
        ME,
        headers={**_cookie(token), "Content-Type": "application/merge-patch+json"},
        content=json.dumps({"nickname": "anna"}),
    )

    assert response.status_code == 200
    assert await _stored_nickname(user.id) == "anna"


async def test_non_json_body_is_rejected(client: httpx.AsyncClient) -> None:
    user = await _user()
    token = await _signed_in(user)

    response = await client.patch(
        ME,
        headers={**_cookie(token), "Content-Type": "text/plain"},
        content=json.dumps({"nickname": "anna"}),
    )

    assert response.status_code == 422
    assert await _stored_nickname(user.id) is None


@pytest.mark.parametrize(
    ("body", "field"),
    [({"nickname": None}, "nickname"), ({"nickname": "anna", "email": "x@y.z"}, "email")],
    ids=["null_nickname", "unknown_field"],
)
async def test_malformed_patch_is_422(
    client: httpx.AsyncClient, body: dict[str, Any], field: str
) -> None:
    user = await _user(nickname="boris")
    token = await _signed_in(user)

    response = await _patch(client, token, body)

    assert response.status_code == 422
    assert response.headers["content-type"] == PROBLEM_JSON
    assert ["body", field] in [error["loc"] for error in response.json()["errors"]]
    assert await _stored_nickname(user.id) == "boris"


async def test_invalid_nickname_is_422_with_reason(client: httpx.AsyncClient) -> None:
    token = await _signed_in(await _user())

    response = await _patch(client, token, {"nickname": "ab"})

    assert response.status_code == 422
    assert response.headers["content-type"] == PROBLEM_JSON
    assert response.json()["type"] == "/problems/nickname-invalid"
    assert response.json()["errors"] == [
        {"loc": ["body", "nickname"], "msg": "Nickname is too short", "type": "too_short"}
    ]


async def test_same_nickname_in_other_case_writes_nothing(client: httpx.AsyncClient) -> None:
    user = await _user(nickname="anna")
    token = await _signed_in(user)

    response = await _patch(client, token, {"nickname": "ANNA"})

    assert response.status_code == 200
    assert response.json()["nickname"] == "anna"
    assert await _quarantine() == {}


async def test_nickname_of_another_user_is_409(client: httpx.AsyncClient) -> None:
    await _user(nickname="anna")
    user = await _user(nickname="boris")
    token = await _signed_in(user)

    response = await _patch(client, token, {"nickname": "Anna"})

    assert response.status_code == 409
    assert response.headers["content-type"] == PROBLEM_JSON
    assert response.json()["type"] == "/problems/nickname-taken"
    assert await _stored_nickname(user.id) == "boris"


async def test_released_nickname_is_kept_for_its_former_owner(client: httpx.AsyncClient) -> None:
    former = await _user(nickname="anna")
    former_token = await _signed_in(former)
    other_token = await _signed_in(await _user())

    await _patch(client, former_token, {"nickname": "boris"})
    stolen = await _patch(client, other_token, {"nickname": "anna"})
    returned = await _patch(client, former_token, {"nickname": "anna"})

    assert stolen.status_code == 409
    assert returned.status_code == 200
    assert await _quarantine() == {"boris": former.id}


async def test_quarantine_ends_after_thirty_days(client: httpx.AsyncClient) -> None:
    former_token = await _signed_in(await _user(nickname="anna"))
    other = await _user()
    other_token = await _signed_in(other)
    await _patch(client, former_token, {"nickname": "boris"})
    await _age_release("anna", 30)

    response = await _patch(client, other_token, {"nickname": "anna"})

    assert response.status_code == 200
    assert await _stored_nickname(other.id) == "anna"
    assert "anna" not in await _quarantine()


async def test_nickname_of_deleted_account_stays_quarantined(client: httpx.AsyncClient) -> None:
    former = await _user(nickname="anna")
    await _patch(client, await _signed_in(former), {"nickname": "boris"})
    await _delete_user(former.id)
    other_token = await _signed_in(await _user())

    response = await _patch(client, other_token, {"nickname": "anna"})

    assert response.status_code == 409
    assert await _quarantine() == {"anna": None}


async def test_fourth_change_in_a_day_is_429(client: httpx.AsyncClient) -> None:
    user = await _user()
    token = await _signed_in(user)

    accepted = [
        (await _patch(client, token, {"nickname": nickname})).status_code
        for nickname in ("anna", "boris", "clara", "daria")
    ]
    refused = await _patch(client, token, {"nickname": "elena"})

    assert accepted == [200, 200, 200, 200]
    assert refused.status_code == 429
    assert refused.json()["type"] == "/problems/rate-limited"
    assert 1 <= int(refused.headers["retry-after"]) <= 86_400
    assert await _stored_nickname(user.id) == "daria"
    assert "daria" not in await _quarantine()


async def test_refused_attempts_do_not_spend_the_limit(client: httpx.AsyncClient) -> None:
    await _user(nickname="taken")
    token = await _signed_in(await _user(nickname="anna"))

    refused = [
        (await _patch(client, token, {"nickname": nickname})).status_code
        for nickname in ("taken", "taken", "ab", "admin")
    ]
    accepted = [
        (await _patch(client, token, {"nickname": nickname})).status_code
        for nickname in ("boris", "clara", "daria")
    ]

    assert refused == [409, 409, 422, 422]
    assert accepted == [200, 200, 200]


async def test_patch_with_limiter_down_is_503_and_keeps_nickname(
    app: FastAPI, client: httpx.AsyncClient, dead_redis: Redis
) -> None:
    user = await _user(nickname="anna")
    token = await _signed_in(user)
    _limiter_down(app, dead_redis)

    response = await _patch(client, token, {"nickname": "boris"})

    assert response.status_code == 503
    assert response.headers["content-type"] == PROBLEM_JSON
    assert await _stored_nickname(user.id) == "anna"
    assert await _quarantine() == {}


async def test_patch_by_user_deleted_after_authentication_is_401(
    app: FastAPI, client: httpx.AsyncClient
) -> None:
    user = await _user(nickname="anna")
    token = await _signed_in(user)
    stale = UserDTO(
        id=user.id,
        nickname="anna",
        email=user.email,
        display_name=user.display_name,
        avatar_url=None,
        email_verified_at=None,
        credentials_version=0,
    )
    await _delete_user(user.id)
    app.dependency_overrides[get_current_user] = lambda: stale

    response = await _patch(client, token, {"nickname": "boris"})

    assert response.status_code == 401
    assert await _quarantine() == {}


async def test_patch_needs_a_session(client: httpx.AsyncClient) -> None:
    response = await client.patch(ME, json={"nickname": "anna"})

    assert response.status_code == 401


async def test_parallel_claims_of_one_nickname_have_one_winner(
    client: httpx.AsyncClient,
) -> None:
    users = [await _user() for _ in range(5)]
    tokens = [await _signed_in(user) for user in users]

    responses = await asyncio.gather(
        *(_patch(client, token, {"nickname": "anna"}) for token in tokens)
    )

    assert sorted(response.status_code for response in responses) == [200, 409, 409, 409, 409]
    owners = [user.id for user in users if await _stored_nickname(user.id) == "anna"]
    assert len(owners) == 1


async def test_crossing_swaps_never_deadlock(client: httpx.AsyncClient) -> None:
    first = await _user(nickname="anna")
    second = await _user(nickname="boris")
    first_token = await _signed_in(first)
    second_token = await _signed_in(second)

    statuses: Counter[int] = Counter()
    for _ in range(10):
        responses = await asyncio.wait_for(
            asyncio.gather(
                _patch(client, first_token, {"nickname": "boris"}),
                _patch(client, second_token, {"nickname": "anna"}),
            ),
            timeout=10,
        )
        statuses.update(response.status_code for response in responses)

    assert statuses == Counter({409: 20})
    assert await _stored_nickname(first.id) == "anna"
    assert await _stored_nickname(second.id) == "boris"


async def test_burst_from_user_without_nickname_respects_the_limit(
    client: httpx.AsyncClient,
) -> None:
    user = await _user()
    token = await _signed_in(user)

    responses = await asyncio.gather(
        *(_patch(client, token, {"nickname": f"cook_{index}"}) for index in range(10))
    )

    statuses = Counter(response.status_code for response in responses)
    released = await _quarantine()
    assert set(statuses) <= {200, 429}
    assert 1 <= statuses[200] <= 4
    assert len(released) == statuses[200] - 1
    assert set(released.values()) <= {user.id}


async def test_parallel_changes_by_one_user_apply_one_after_another(
    client: httpx.AsyncClient,
) -> None:
    user = await _user(nickname="anna")
    token = await _signed_in(user)

    responses = await asyncio.gather(
        _patch(client, token, {"nickname": "boris"}),
        _patch(client, token, {"nickname": "clara"}),
    )

    final = await _stored_nickname(user.id)
    assert [response.status_code for response in responses] == [200, 200]
    assert final in {"boris", "clara"}
    assert set(await _quarantine()) == {"anna", "boris", "clara"} - {final}


async def test_free_nickname_is_available(client: httpx.AsyncClient) -> None:
    token = await _signed_in(await _user(nickname="anna"))

    response = await _check(client, token, " Boris ")

    assert response.status_code == 200
    assert response.json() == {"nickname": "boris", "available": True, "reason": None}
    assert response.headers["cache-control"] == "no-store"


async def test_nickname_of_another_user_is_not_available(client: httpx.AsyncClient) -> None:
    await _user(nickname="boris")
    token = await _signed_in(await _user(nickname="anna"))

    response = await _check(client, token, "boris")

    assert response.json() == {"nickname": "boris", "available": False, "reason": "taken"}


async def test_own_nickname_is_available(client: httpx.AsyncClient) -> None:
    token = await _signed_in(await _user(nickname="anna"))

    response = await _check(client, token, "Anna")

    assert response.json() == {"nickname": "anna", "available": True, "reason": None}


async def test_quarantine_shows_as_taken_to_others_only(client: httpx.AsyncClient) -> None:
    former_token = await _signed_in(await _user(nickname="anna"))
    other_token = await _signed_in(await _user())
    await _patch(client, former_token, {"nickname": "boris"})

    for_others = await _check(client, other_token, "anna")
    for_former = await _check(client, former_token, "anna")

    assert for_others.json()["reason"] == "taken"
    assert for_former.json()["available"] is True


@pytest.mark.parametrize(
    ("raw", "reason"),
    [("", "too_short"), ("a b c", "bad_characters"), ("admin", "reserved")],
)
async def test_invalid_nickname_is_200_with_reason(
    client: httpx.AsyncClient, raw: str, reason: str
) -> None:
    token = await _signed_in(await _user())

    response = await _check(client, token, raw)

    assert response.status_code == 200
    assert response.json() == {"nickname": None, "available": False, "reason": reason}


async def test_check_without_parameter_is_422(client: httpx.AsyncClient) -> None:
    token = await _signed_in(await _user())

    response = await client.get(AVAILABILITY, headers=_cookie(token))

    assert response.status_code == 422
    assert response.json()["errors"][0]["loc"] == ["query", "nickname"]


async def test_check_needs_a_session(client: httpx.AsyncClient) -> None:
    response = await client.get(AVAILABILITY, params={"nickname": "anna"})

    assert response.status_code == 401


async def test_check_changes_nothing(client: httpx.AsyncClient) -> None:
    user = await _user()
    token = await _signed_in(user)

    await _check(client, token, "anna")

    assert await _stored_nickname(user.id) is None
    assert await _quarantine() == {}


async def test_sixty_first_check_in_a_minute_is_429(client: httpx.AsyncClient) -> None:
    token = await _signed_in(await _user())
    neighbour_token = await _signed_in(await _user())

    statuses = [(await _check(client, token, "anna")).status_code for _ in range(60)]
    refused = await _check(client, token, "anna")
    neighbour = await _check(client, neighbour_token, "anna")

    assert set(statuses) == {200}
    assert refused.status_code == 429
    assert 1 <= int(refused.headers["retry-after"]) <= 60
    assert neighbour.status_code == 200


async def test_check_with_limiter_down_is_503(
    app: FastAPI, client: httpx.AsyncClient, dead_redis: Redis
) -> None:
    token = await _signed_in(await _user())
    _limiter_down(app, dead_redis)

    response = await _check(client, token, "anna")

    assert response.status_code == 503


@pytest.fixture
def gated(app: FastAPI) -> FastAPI:
    @app.get(GATED)
    async def gated_route(
        user: Annotated[UserDTO, Depends(require_nickname)],
        current: Annotated[UserDTO, Depends(get_current_user)],
    ) -> dict[str, str | None]:
        return {"nickname": user.nickname, "current": current.nickname}

    return app


async def test_gate_stops_user_without_nickname(gated: FastAPI, client: httpx.AsyncClient) -> None:
    token = await _signed_in(await _user())

    response = await client.get(GATED, headers=_cookie(token))

    assert response.status_code == 403
    assert response.headers["content-type"] == PROBLEM_JSON
    assert response.json()["type"] == "/problems/nickname-required"


async def test_gate_lets_user_with_nickname_through(
    gated: FastAPI, client: httpx.AsyncClient
) -> None:
    token = await _signed_in(await _user(nickname="anna"))

    response = await client.get(GATED, headers=_cookie(token))

    assert response.status_code == 200
    assert response.json() == {"nickname": "anna", "current": "anna"}


async def test_gate_does_not_resolve_the_session_twice(
    gated: FastAPI, client: httpx.AsyncClient
) -> None:
    counting = CountingStore(_store(get_redis()))
    gated.dependency_overrides[get_session_store] = lambda: counting
    token = await _signed_in(await _user(nickname="anna"))

    await client.get(GATED, headers=_cookie(token))

    assert counting.resolves == 1


async def test_gate_needs_a_session(gated: FastAPI, client: httpx.AsyncClient) -> None:
    response = await client.get(GATED)

    assert response.status_code == 401


@pytest.mark.parametrize("path", [ME, AVAILABILITY])
async def test_profile_and_check_work_without_nickname(
    client: httpx.AsyncClient, path: str
) -> None:
    token = await _signed_in(await _user())

    response = await client.get(path, params={"nickname": "anna"}, headers=_cookie(token))

    assert response.status_code == 200


def test_openapi_documents_nickname_endpoints(app: FastAPI) -> None:
    paths = app.openapi()["paths"]
    patch = paths[ME]["patch"]
    check = paths[AVAILABILITY]["get"]

    assert {"200", "401", "409", "422", "429", "503"} <= set(patch["responses"])
    assert {"200", "401", "422", "429", "503"} <= set(check["responses"])
    assert check["parameters"][0]["name"] == "nickname"
    assert check["parameters"][0]["in"] == "query"
    assert check["parameters"][0]["required"] is True
