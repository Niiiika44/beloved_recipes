import socket
import time
import uuid
from collections.abc import AsyncIterator, Callable
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from typing import Any

import httpx
import pytest
from fastapi import FastAPI
from redis.asyncio import Redis
from sqlalchemy import text
from sqlalchemy.pool import QueuePool

from app.core.config import get_settings
from app.core.db import dispose_engine, get_engine, get_session_factory
from app.core.redis import close_redis, get_redis
from app.main import create_app
from app.modules.identity.domain.enums import WorkspaceRole
from app.modules.identity.infrastructure.models import Membership, User, Workspace
from app.modules.identity.infrastructure.redis_session_store import RedisSessionStore
from app.modules.identity.routes.dependencies import get_session_store
from app.modules.identity.service.dto import SessionDTO

ME = "/api/v1/users/me"
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


def _free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port: int = probe.getsockname()[1]
    return port


def _checked_out() -> int:
    pool = get_engine().pool
    assert isinstance(pool, QueuePool)
    return pool.checkedout()


class CountingStore:
    def __init__(self, inner: RedisSessionStore) -> None:
        self._inner = inner
        self.resolves = 0

    async def create(self, user_id: uuid.UUID) -> str:
        return await self._inner.create(user_id)

    async def resolve(self, token: str) -> SessionDTO | None:
        self.resolves += 1
        return await self._inner.resolve(token)

    async def revoke(self, token: str) -> None:
        await self._inner.revoke(token)


@pytest.fixture
async def app(migrated_schema: None, _point_redis_at_container: None) -> AsyncIterator[FastAPI]:
    get_engine.cache_clear()
    get_session_factory.cache_clear()
    get_redis.cache_clear()
    await get_redis().flushdb()
    application = create_app()

    yield application

    application.dependency_overrides.clear()
    async with get_engine().begin() as connection:
        await connection.execute(text("TRUNCATE users, workspaces, memberships, invites CASCADE"))
    await dispose_engine()
    await close_redis()


@pytest.fixture
async def client(app: FastAPI) -> AsyncIterator[httpx.AsyncClient]:
    transport = httpx.ASGITransport(app, raise_app_exceptions=False)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as instance:
        yield instance


@pytest.fixture
async def dead_redis() -> AsyncIterator[Redis]:
    client = Redis(host="127.0.0.1", port=_free_port(), decode_responses=True)

    yield client

    await client.aclose()


async def _user(**overrides: Any) -> User:
    suffix = uuid.uuid4().hex[:8]
    values: dict[str, Any] = {
        "email": f"cook-{suffix}@example.com",
        "google_sub": f"sub-{suffix}",
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
    return await _store(get_redis()).create(user.id)


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
    token = await _store(get_redis(), now=lambda: long_ago).create(user.id)

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
