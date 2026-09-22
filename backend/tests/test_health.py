import asyncio
import os
from collections.abc import AsyncIterator
from time import perf_counter
from typing import Self

import httpx
import pytest
import structlog

from app.core.config import get_settings
from app.core.db import dispose_engine, get_engine, get_session_factory
from app.core.redis import close_redis, get_redis
from app.main import create_app

UNREACHABLE_PORT = "1"
SHORT_BUDGET = 0.3


class HangingRedis:
    async def ping(self) -> bool:
        await asyncio.sleep(3600)
        return True


class HangingEngine:
    def connect(self) -> Self:
        return self

    async def __aenter__(self) -> Self:
        await asyncio.sleep(3600)
        return self

    async def __aexit__(self, *args: object) -> None:
        return None


async def _reset_clients() -> None:
    if get_engine.cache_info().currsize:
        await dispose_engine()
    if get_redis.cache_info().currsize:
        await close_redis()
    get_session_factory.cache_clear()
    get_settings.cache_clear()


async def _break(monkeypatch: pytest.MonkeyPatch, *sections: str) -> None:
    for section in sections:
        monkeypatch.setenv(f"{section}__PORT", UNREACHABLE_PORT)
    await _reset_clients()


@pytest.fixture(autouse=True)
async def _stack(_point_at_container: None, _point_redis_at_container: None) -> AsyncIterator[None]:
    await _reset_clients()

    yield

    await _reset_clients()


@pytest.fixture
async def client() -> AsyncIterator[httpx.AsyncClient]:
    transport = httpx.ASGITransport(create_app())
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as instance:
        yield instance


async def test_healthz_is_ok(client: httpx.AsyncClient) -> None:
    response = await client.get("/healthz")

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


async def test_healthz_ignores_dependencies(
    client: httpx.AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    await _break(monkeypatch, "DB", "REDIS")
    started = perf_counter()

    response = await client.get("/healthz")

    assert response.status_code == 200
    assert perf_counter() - started < 0.5


async def test_readyz_is_ok_when_dependencies_are_up(client: httpx.AsyncClient) -> None:
    response = await client.get("/readyz")

    assert response.status_code == 200
    assert response.json() == {"status": "ok", "checks": {"postgres": "ok", "redis": "ok"}}


async def test_readyz_reports_redis_outage(
    client: httpx.AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    await _break(monkeypatch, "REDIS")

    response = await client.get("/readyz")

    assert response.status_code == 503
    assert response.json() == {"status": "fail", "checks": {"postgres": "ok", "redis": "fail"}}


async def test_readyz_reports_postgres_outage(
    client: httpx.AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    await _break(monkeypatch, "DB")

    response = await client.get("/readyz")

    assert response.status_code == 503
    assert response.json() == {"status": "fail", "checks": {"postgres": "fail", "redis": "ok"}}


async def test_readyz_reports_both_outages(
    client: httpx.AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    await _break(monkeypatch, "DB", "REDIS")

    response = await client.get("/readyz")

    assert response.status_code == 503
    assert response.json()["checks"] == {"postgres": "fail", "redis": "fail"}


async def test_readyz_recovers_without_restart(
    client: httpx.AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    real_port = os.environ["REDIS__PORT"]
    await _break(monkeypatch, "REDIS")
    assert (await client.get("/readyz")).status_code == 503

    monkeypatch.setenv("REDIS__PORT", real_port)
    await _reset_clients()

    assert (await client.get("/readyz")).status_code == 200


async def test_readyz_hides_failure_details(
    client: httpx.AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    await _break(monkeypatch, "DB", "REDIS")

    body = (await client.get("/readyz")).json()

    assert set(body) == {"status", "checks"}
    assert set(body["checks"].values()) == {"fail"}
    assert get_settings().db.host not in str(body)


async def test_readyz_logs_failure_details(
    client: httpx.AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    await _break(monkeypatch, "REDIS")

    with structlog.testing.capture_logs() as records:
        await client.get("/readyz")

    failures = [record for record in records if record["event"] == "readyz.redis_unavailable"]
    assert len(failures) == 1
    assert failures[0]["error"]


async def test_readyz_is_not_reshaped_into_problem_details(
    client: httpx.AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    await _break(monkeypatch, "REDIS")

    response = await client.get("/readyz")

    assert response.status_code == 503
    assert response.headers["content-type"] == "application/json"


async def test_hanging_redis_is_cut_by_budget(
    client: httpx.AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("app.api.health.CHECK_TIMEOUT_SECONDS", SHORT_BUDGET)
    monkeypatch.setattr("app.api.health.get_redis", HangingRedis)
    started = perf_counter()

    response = await client.get("/readyz")

    assert response.status_code == 503
    assert response.json()["checks"]["redis"] == "fail"
    assert perf_counter() - started < SHORT_BUDGET + 0.5


async def test_hanging_postgres_is_cut_by_budget(
    client: httpx.AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("app.api.health.CHECK_TIMEOUT_SECONDS", SHORT_BUDGET)
    monkeypatch.setattr("app.api.health.get_engine", HangingEngine)
    started = perf_counter()

    response = await client.get("/readyz")

    assert response.status_code == 503
    assert response.json()["checks"]["postgres"] == "fail"
    assert perf_counter() - started < SHORT_BUDGET + 0.5


async def test_checks_run_concurrently(
    client: httpx.AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("app.api.health.CHECK_TIMEOUT_SECONDS", SHORT_BUDGET)
    monkeypatch.setattr("app.api.health.get_redis", HangingRedis)
    monkeypatch.setattr("app.api.health.get_engine", HangingEngine)
    started = perf_counter()

    response = await client.get("/readyz")

    assert response.json()["checks"] == {"postgres": "fail", "redis": "fail"}
    assert perf_counter() - started < SHORT_BUDGET * 2


@pytest.mark.parametrize("path", ["/api/v1/healthz", "/api/v1/readyz"])
async def test_probes_live_outside_api_prefix(client: httpx.AsyncClient, path: str) -> None:
    response = await client.get(path)

    assert response.status_code == 404
