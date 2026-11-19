import os
import socket
from collections.abc import AsyncIterator, Iterator, Mapping
from pathlib import Path

import httpx
import pytest
from alembic.config import Config
from fastapi import FastAPI
from redis.asyncio import Redis
from sqlalchemy import text
from testcontainers.community.postgres import PostgresContainer
from testcontainers.community.redis import RedisContainer

from alembic import command
from app.core.config import get_settings
from app.core.db import dispose_engine, get_engine, get_session_factory
from app.core.redis import close_redis, get_redis
from app.main import create_app
from app.modules.identity.routes.dependencies import get_password_hasher

REDIS_TEST_PASSWORD = "test-redis-password"
ALEMBIC_INI = Path(__file__).resolve().parents[1] / "alembic.ini"

os.environ.setdefault("GOOGLE__CLIENT_ID", "test-client-id.apps.googleusercontent.com")
os.environ.setdefault("GOOGLE__CLIENT_SECRET", "test-google-client-secret")


def _override_env(overrides: Mapping[str, str]) -> Iterator[None]:
    saved = {key: os.environ.get(key) for key in overrides}
    os.environ.update(overrides)
    get_settings.cache_clear()

    yield

    for key, value in saved.items():
        if value is None:
            os.environ.pop(key, None)
        else:
            os.environ[key] = value
    get_settings.cache_clear()


@pytest.fixture(scope="session")
def postgres() -> Iterator[PostgresContainer]:
    with PostgresContainer("postgres:17-alpine") as container:
        yield container


@pytest.fixture(scope="session")
def redis_server() -> Iterator[RedisContainer]:
    with RedisContainer("redis:7-alpine", password=REDIS_TEST_PASSWORD) as container:
        yield container


@pytest.fixture(scope="session")
def _point_at_container(postgres: PostgresContainer) -> Iterator[None]:
    yield from _override_env(
        {
            "DB__HOST": postgres.get_container_host_ip(),
            "DB__PORT": str(postgres.get_exposed_port(5432)),
            "DB__USER": postgres.username,
            "DB__PASSWORD": postgres.password,
            "DB__NAME": postgres.dbname,
        }
    )


@pytest.fixture(scope="session")
def _point_redis_at_container(redis_server: RedisContainer) -> Iterator[None]:
    yield from _override_env(
        {
            "REDIS__HOST": redis_server.get_container_host_ip(),
            "REDIS__PORT": str(redis_server.get_exposed_port(6379)),
            "REDIS__PASSWORD": REDIS_TEST_PASSWORD,
        }
    )


@pytest.fixture(scope="module")
def migrated_schema(_point_at_container: None) -> Iterator[None]:
    config = Config(str(ALEMBIC_INI))
    command.upgrade(config, "head")

    yield

    command.downgrade(config, "base")


def _free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port: int = probe.getsockname()[1]
    return port


@pytest.fixture
async def app(migrated_schema: None, _point_redis_at_container: None) -> AsyncIterator[FastAPI]:
    get_engine.cache_clear()
    get_session_factory.cache_clear()
    get_redis.cache_clear()
    get_password_hasher.cache_clear()
    await get_redis().flushdb()
    application = create_app()

    yield application

    application.dependency_overrides.clear()
    async with get_engine().begin() as connection:
        await connection.execute(text("TRUNCATE users, workspaces, memberships, invites CASCADE"))
    await dispose_engine()
    await close_redis()
    get_password_hasher.cache_clear()


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
