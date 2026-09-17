import os
from collections.abc import Iterator

import pytest
from testcontainers.community.postgres import PostgresContainer

from app.core.config import get_settings


@pytest.fixture(scope="session")
def postgres() -> Iterator[PostgresContainer]:
    with PostgresContainer("postgres:17-alpine") as container:
        yield container


@pytest.fixture(scope="session")
def _point_at_container(postgres: PostgresContainer) -> Iterator[None]:
    overrides = {
        "DB__HOST": postgres.get_container_host_ip(),
        "DB__PORT": str(postgres.get_exposed_port(5432)),
        "DB__USER": postgres.username,
        "DB__PASSWORD": postgres.password,
        "DB__NAME": postgres.dbname,
    }
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
