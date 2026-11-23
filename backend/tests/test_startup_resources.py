import asyncio
import time
from collections import Counter
from collections.abc import AsyncIterator, Iterator
from contextlib import asynccontextmanager
from typing import Any

import httpx
import pytest
import redis.asyncio
import redis.exceptions
from fastapi import FastAPI
from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.pool import NullPool

import app.core.db
from app.core.config import get_settings
from app.core.db import get_engine, get_session_factory
from app.core.redis import close_redis, get_redis
from app.main import create_app, lifespan

LOGIN = "/api/v1/auth/login"
PROBLEM_JSON = "application/problem+json"


@pytest.fixture
def fresh_process(
    migrated_schema: None, _point_redis_at_container: None, monkeypatch: pytest.MonkeyPatch
) -> Iterator[None]:
    monkeypatch.setattr("app.main.configure_logging", lambda: None)
    get_settings.cache_clear()
    get_engine.cache_clear()
    get_session_factory.cache_clear()
    get_redis.cache_clear()

    yield

    get_settings.cache_clear()
    get_engine.cache_clear()
    get_session_factory.cache_clear()
    get_redis.cache_clear()


@pytest.fixture
def slow_engines(monkeypatch: pytest.MonkeyPatch) -> list[Any]:
    created: list[Any] = []
    real = create_async_engine

    def slow(*args: Any, **kwargs: Any) -> Any:
        time.sleep(0.05)
        engine = real(*args, **kwargs)
        created.append(engine)
        return engine

    monkeypatch.setattr(app.core.db, "create_async_engine", slow)
    return created


@asynccontextmanager
async def _running() -> AsyncIterator[httpx.AsyncClient]:
    application: FastAPI = create_app()
    async with lifespan(application):
        await get_redis().flushdb()
        transport = httpx.ASGITransport(application, raise_app_exceptions=False)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            yield client


async def _login(client: httpx.AsyncClient, index: int) -> httpx.Response:
    return await client.post(
        LOGIN, json={"email": f"cook{index}@example.org", "password": "wrong horse battery"}
    )


async def _hold_the_only_connection(seconds: float) -> None:
    await get_redis().blpop(["nothing-arrives"], timeout=seconds)


async def _database_connections() -> int:
    probe = create_async_engine(get_settings().db.dsn, poolclass=NullPool)
    try:
        async with probe.connect() as connection:
            count = await connection.scalar(
                text(
                    "SELECT count(*) FROM pg_stat_activity "
                    "WHERE datname = current_database() AND pid <> pg_backend_pid()"
                )
            )
    finally:
        await probe.dispose()
    return int(count or 0)


async def _redis_clients() -> int:
    settings = get_settings().redis
    probe = redis.asyncio.Redis(
        host=settings.host, port=settings.port, password=settings.password.get_secret_value()
    )
    try:
        info = await probe.info("clients")
    finally:
        await probe.aclose()
    return int(info["connected_clients"]) - 1


@pytest.mark.usefixtures("fresh_process")
async def test_first_parallel_requests_after_start_share_one_engine(
    slow_engines: list[Any],
) -> None:
    async with _running() as client:
        responses = await asyncio.gather(*(_login(client, index) for index in range(10)))

    assert [response.status_code for response in responses] == [401] * 10
    assert len(slow_engines) == 1


@pytest.mark.usefixtures("fresh_process")
async def test_no_database_connection_outlives_the_application(
    slow_engines: list[Any],
) -> None:
    before = await _database_connections()

    async with _running() as client:
        await asyncio.gather(*(_login(client, index) for index in range(10)))
        during = await _database_connections()

    assert during > before
    assert await _database_connections() == before


@pytest.mark.usefixtures("fresh_process")
async def test_no_redis_connection_outlives_the_application() -> None:
    before = await _redis_clients()

    async with _running() as client:
        await asyncio.gather(*(_login(client, index) for index in range(10)))
        during = await _redis_clients()

    assert during > before
    assert await _redis_clients() == before


@pytest.mark.usefixtures("fresh_process")
async def test_burst_larger_than_the_redis_pool_waits_instead_of_failing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("REDIS__MAX_CONNECTIONS", "1")

    async with _running() as client:
        responses = await asyncio.gather(*(_login(client, index) for index in range(30)))

    assert Counter(response.status_code for response in responses) == Counter({401: 30})


@pytest.mark.usefixtures("fresh_process")
async def test_redis_pool_exhausted_past_the_wait_is_503(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("REDIS__MAX_CONNECTIONS", "1")
    monkeypatch.setenv("REDIS__POOL_TIMEOUT_SECONDS", "0.1")

    async with _running() as client:
        holder = asyncio.create_task(_hold_the_only_connection(1))
        await asyncio.sleep(0.05)
        started = time.monotonic()
        response = await _login(client, 0)
        elapsed = time.monotonic() - started
        await holder

    assert response.status_code == 503
    assert response.headers["content-type"] == PROBLEM_JSON
    assert elapsed < 0.6


@pytest.mark.usefixtures("fresh_process")
async def test_redis_client_decodes_responses() -> None:
    client = get_redis()

    await client.set("probe", "значение")

    assert await client.get("probe") == "значение"
    await close_redis()


@pytest.mark.usefixtures("fresh_process")
async def test_redis_pool_waits_before_giving_up(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("REDIS__MAX_CONNECTIONS", "1")
    monkeypatch.setenv("REDIS__POOL_TIMEOUT_SECONDS", "0.2")
    client = get_redis()
    holder = asyncio.create_task(_hold_the_only_connection(0.5))
    await asyncio.sleep(0.05)

    started = time.monotonic()
    with pytest.raises(redis.exceptions.ConnectionError):
        await client.ping()
    waited = time.monotonic() - started

    await holder
    assert await client.ping() is True
    assert 0.15 <= waited < 0.45
    await close_redis()
