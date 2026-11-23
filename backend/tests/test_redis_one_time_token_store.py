import asyncio
import re
import socket
import time
import uuid
from collections.abc import AsyncIterator
from datetime import timedelta
from hashlib import sha256
from typing import Any, cast

import pytest
from redis.asyncio import Redis
from redis.asyncio.retry import Retry
from redis.backoff import NoBackoff

from app.core.exceptions import DependencyUnavailableError
from app.core.redis import close_redis, get_redis
from app.modules.identity.domain.enums import TokenPurpose
from app.modules.identity.infrastructure.exceptions import OneTimeTokenStoreUnavailableError
from app.modules.identity.infrastructure.redis_one_time_token_store import RedisOneTimeTokenStore
from app.modules.identity.service.ports import OneTimeTokenStore

TOKEN_PATTERN = re.compile(r"[A-Za-z0-9_-]{43}")
DAY = timedelta(hours=24)
USER = uuid.UUID("01900000-0000-7000-8000-000000000001")


class UntouchableRedis:
    def __getattr__(self, name: str) -> Any:
        raise AssertionError(f"Redis must not be called, got {name}")


def _free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port: int = probe.getsockname()[1]
    return port


@pytest.fixture
async def redis_client(_point_redis_at_container: None) -> AsyncIterator[Redis]:
    get_redis.cache_clear()
    client = get_redis()
    await client.flushdb()

    yield client

    await close_redis()


@pytest.fixture
def store(redis_client: Redis) -> RedisOneTimeTokenStore:
    return RedisOneTimeTokenStore(client=redis_client, operation_timeout_seconds=1.0)


@pytest.fixture
async def refusing_redis() -> AsyncIterator[Redis]:
    client = Redis(
        host="127.0.0.1",
        port=_free_port(),
        socket_connect_timeout=5,
        socket_timeout=5,
        retry=Retry(NoBackoff(), 0),
    )

    yield client

    await client.aclose()


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


def test_satisfies_the_port(store: RedisOneTimeTokenStore) -> None:
    port: OneTimeTokenStore = store

    assert port is store


async def test_issued_token_is_long_and_url_safe(store: RedisOneTimeTokenStore) -> None:
    token = await store.issue(TokenPurpose.EMAIL_CONFIRM, USER, DAY)

    assert TOKEN_PATTERN.fullmatch(token)


async def test_tokens_are_unique(store: RedisOneTimeTokenStore) -> None:
    tokens = {await store.issue(TokenPurpose.EMAIL_CONFIRM, USER, DAY) for _ in range(20)}

    assert len(tokens) == 20


async def test_only_the_hash_of_the_token_reaches_redis(
    store: RedisOneTimeTokenStore, redis_client: Redis
) -> None:
    token = await store.issue(TokenPurpose.EMAIL_CONFIRM, USER, DAY)

    assert await redis_client.keys("*") == [
        "auth_token:email_confirm:" + sha256(token.encode()).hexdigest()
    ]


async def test_token_lives_for_the_given_ttl(
    store: RedisOneTimeTokenStore, redis_client: Redis
) -> None:
    await store.issue(TokenPurpose.PASSWORD_RESET, USER, timedelta(hours=1))

    [key] = await redis_client.keys("*")
    assert 3590 <= await redis_client.ttl(key) <= 3600


async def test_token_resolves_to_its_user(store: RedisOneTimeTokenStore) -> None:
    token = await store.issue(TokenPurpose.EMAIL_CONFIRM, USER, DAY)

    assert await store.consume(TokenPurpose.EMAIL_CONFIRM, token) == USER


async def test_token_works_only_once(store: RedisOneTimeTokenStore) -> None:
    token = await store.issue(TokenPurpose.EMAIL_CONFIRM, USER, DAY)
    await store.consume(TokenPurpose.EMAIL_CONFIRM, token)

    assert await store.consume(TokenPurpose.EMAIL_CONFIRM, token) is None


async def test_parallel_consumes_succeed_once(
    store: RedisOneTimeTokenStore, redis_client: Redis
) -> None:
    token = await store.issue(TokenPurpose.EMAIL_CONFIRM, USER, DAY)

    results = await asyncio.gather(
        *(store.consume(TokenPurpose.EMAIL_CONFIRM, token) for _ in range(10))
    )

    assert results.count(USER) == 1
    assert await redis_client.keys("*") == []


async def test_token_of_another_purpose_is_refused(store: RedisOneTimeTokenStore) -> None:
    token = await store.issue(TokenPurpose.PASSWORD_RESET, USER, DAY)

    assert await store.consume(TokenPurpose.EMAIL_CONFIRM, token) is None
    assert await store.consume(TokenPurpose.PASSWORD_RESET, token) == USER


async def test_unknown_token_is_refused(store: RedisOneTimeTokenStore) -> None:
    assert await store.consume(TokenPurpose.EMAIL_CONFIRM, "A" * 43) is None


async def test_expired_token_is_refused(store: RedisOneTimeTokenStore, redis_client: Redis) -> None:
    token = await store.issue(TokenPurpose.EMAIL_CONFIRM, USER, DAY)
    [key] = await redis_client.keys("*")
    await redis_client.pexpire(key, 50)
    await asyncio.sleep(0.1)

    assert await store.consume(TokenPurpose.EMAIL_CONFIRM, token) is None


@pytest.mark.parametrize("token", ["", "short", "A" * 42, "A" * 44, "A" * 42 + "!"])
async def test_malformed_token_never_reaches_redis(token: str) -> None:
    store = RedisOneTimeTokenStore(
        client=cast(Redis, UntouchableRedis()), operation_timeout_seconds=1.0
    )

    assert await store.consume(TokenPurpose.EMAIL_CONFIRM, token) is None


async def test_refused_connection_is_reported_as_unavailable(refusing_redis: Redis) -> None:
    store = RedisOneTimeTokenStore(client=refusing_redis, operation_timeout_seconds=1.0)

    with pytest.raises(OneTimeTokenStoreUnavailableError) as caught:
        async with asyncio.timeout(5):
            await store.issue(TokenPurpose.EMAIL_CONFIRM, USER, DAY)

    assert isinstance(caught.value, DependencyUnavailableError)


async def test_hanging_redis_is_cut_by_operation_timeout(silent_redis: Redis) -> None:
    store = RedisOneTimeTokenStore(client=silent_redis, operation_timeout_seconds=0.3)
    started = time.monotonic()

    with pytest.raises(OneTimeTokenStoreUnavailableError) as caught:
        async with asyncio.timeout(5):
            await store.consume(TokenPurpose.EMAIL_CONFIRM, "A" * 43)

    assert time.monotonic() - started < 1.5
    assert isinstance(caught.value.__cause__, TimeoutError)
