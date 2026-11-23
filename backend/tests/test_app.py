import logging
import socket
from collections.abc import Iterator

import httpx
import pytest
import structlog
from starlette.requests import Request

from app.core.config import get_settings
from app.core.db import get_engine, get_session_factory
from app.core.redis import get_redis
from app.main import create_app, lifespan
from app.modules.identity.infrastructure.argon2_password_hasher import Argon2PasswordHasher
from app.modules.identity.routes.dependencies import get_password_hasher

PROD_SECRET = "p" * 40


def _clear_caches() -> None:
    get_engine.cache_clear()
    get_session_factory.cache_clear()
    get_redis.cache_clear()
    get_settings.cache_clear()


@pytest.fixture(autouse=True)
def _isolate() -> Iterator[None]:
    root = logging.getLogger()
    saved_handlers, saved_level = list(root.handlers), root.level
    _clear_caches()

    yield

    root.handlers[:] = saved_handlers
    root.setLevel(saved_level)
    structlog.reset_defaults()
    _clear_caches()


@pytest.fixture
def quiet_logging(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("app.main.configure_logging", lambda: None)


async def _get(path: str) -> httpx.Response:
    transport = httpx.ASGITransport(create_app())
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        return await client.get(path)


@pytest.mark.parametrize("path", ["/docs", "/redoc", "/openapi.json"])
async def test_docs_are_available_outside_prod(monkeypatch: pytest.MonkeyPatch, path: str) -> None:
    monkeypatch.setenv("APP__ENV", "local")
    get_settings.cache_clear()

    assert (await _get(path)).status_code == 200


@pytest.mark.parametrize("path", ["/docs", "/redoc", "/openapi.json"])
async def test_docs_are_hidden_in_prod(monkeypatch: pytest.MonkeyPatch, path: str) -> None:
    monkeypatch.setenv("APP__ENV", "prod")
    monkeypatch.setenv("SECURITY__SECRET_KEY", PROD_SECRET)
    monkeypatch.setenv("SESSION__COOKIE_NAME", "__Host-session")
    monkeypatch.setenv("SESSION__COOKIE_SECURE", "true")
    monkeypatch.setenv("APP__PUBLIC_BASE_URL", "https://recipes.ru")
    monkeypatch.setenv("MAIL__TLS", "tls")
    monkeypatch.setenv("MAIL__SENDER_ADDRESS", "no-reply@recipes.ru")
    get_settings.cache_clear()

    assert (await _get(path)).status_code == 404


def test_probes_are_documented_at_root() -> None:
    paths = set(create_app().openapi()["paths"])

    assert {"/healthz", "/readyz"} <= paths
    assert not any(path.startswith("/api/v1/") and path.endswith("z") for path in paths)


async def test_exception_handlers_work_without_lifespan() -> None:
    response = await _get("/nope")

    assert response.headers["content-type"] == "application/problem+json"


async def test_lifespan_configures_logging() -> None:
    app = create_app()

    async with lifespan(app):
        handlers = logging.getLogger().handlers

    assert len(handlers) == 1
    assert isinstance(handlers[0].formatter, structlog.stdlib.ProcessorFormatter)


@pytest.mark.usefixtures("quiet_logging")
async def test_lifespan_closes_created_resources() -> None:
    async with lifespan(create_app()):
        get_engine()
        get_redis()

    assert get_engine.cache_info().currsize == 0
    assert get_redis.cache_info().currsize == 0


@pytest.mark.usefixtures("quiet_logging")
async def test_lifespan_creates_engine_and_redis_before_requests() -> None:
    async with lifespan(create_app()):
        assert get_engine.cache_info().currsize == 1
        assert get_session_factory.cache_info().currsize == 1
        assert get_redis.cache_info().currsize == 1
        assert get_session_factory().kw["bind"] is get_engine()


def _free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port: int = probe.getsockname()[1]
    return port


@pytest.mark.usefixtures("quiet_logging")
async def test_application_starts_while_postgres_and_redis_are_down(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("DB__PORT", str(_free_port()))
    monkeypatch.setenv("REDIS__PORT", str(_free_port()))
    get_settings.cache_clear()
    app = create_app()

    async with lifespan(app):
        transport = httpx.ASGITransport(app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            alive = await client.get("/healthz")

    assert alive.status_code == 200
    assert get_engine.cache_info().currsize == 0
    assert get_redis.cache_info().currsize == 0


@pytest.mark.usefixtures("quiet_logging")
async def test_cleanup_failure_does_not_block_other_resources(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    closed: list[str] = []

    async def failing_dispose() -> None:
        raise RuntimeError("engine is gone")

    async def recording_close() -> None:
        closed.append("redis")

    monkeypatch.setattr("app.main.dispose_engine", failing_dispose)
    monkeypatch.setattr("app.main.close_redis", recording_close)

    with structlog.testing.capture_logs() as records:
        async with lifespan(create_app()):
            get_engine()
            get_redis()

    assert closed == ["redis"]
    assert [record["event"] for record in records] == ["app.dispose_engine_unavailable"]


@pytest.mark.usefixtures("quiet_logging")
async def test_redis_close_failure_is_logged_and_not_raised(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def failing_close() -> None:
        raise RuntimeError("redis is gone")

    monkeypatch.setattr("app.main.close_redis", failing_close)

    with structlog.testing.capture_logs() as records:
        async with lifespan(create_app()):
            get_engine()
            get_redis()

    assert get_engine.cache_info().currsize == 0
    assert [record["event"] for record in records] == ["app.redis_close_unavailable"]
    assert records[0]["error"] == "redis is gone"


def _request_to(app: object) -> Request:
    return Request({"type": "http", "app": app, "headers": []})


@pytest.mark.usefixtures("quiet_logging")
async def test_lifespan_builds_the_password_hasher_before_requests() -> None:
    app = create_app()

    async with lifespan(app):
        hasher = app.state.password_hasher

        assert isinstance(hasher, Argon2PasswordHasher)
        assert await get_password_hasher(_request_to(app)) is hasher
        assert await get_password_hasher(_request_to(app)) is hasher


@pytest.mark.usefixtures("quiet_logging")
async def test_each_application_gets_its_own_hasher() -> None:
    first, second = create_app(), create_app()

    async with lifespan(first), lifespan(second):
        assert first.state.password_hasher is not second.state.password_hasher
