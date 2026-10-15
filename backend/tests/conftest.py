import os
from collections.abc import Iterator, Mapping
from pathlib import Path

import pytest
from alembic.config import Config
from testcontainers.community.postgres import PostgresContainer
from testcontainers.community.redis import RedisContainer

from alembic import command
from app.core.config import get_settings

REDIS_TEST_PASSWORD = "test-redis-password"
ALEMBIC_INI = Path(__file__).resolve().parents[1] / "alembic.ini"


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
