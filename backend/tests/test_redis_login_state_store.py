import asyncio
import json
import socket
import time
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
from app.modules.identity.infrastructure.exceptions import LoginStateStoreUnavailableError
from app.modules.identity.infrastructure.redis_login_state_store import RedisLoginStateStore
from app.modules.identity.service.dto import PendingLoginDTO
from app.modules.identity.service.ports import LoginStateStore

STATE = "s" * 20 + "-_" + "T" * 21
TTL = timedelta(minutes=10)
PENDING = PendingLoginDTO(
    code_verifier="V" * 43,
    nonce="N" * 43,
    next="/рецепты/42?tab=steps",
    browser_binding_hash="b" * 64,
)


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
def store(redis_client: Redis) -> RedisLoginStateStore:
    return RedisLoginStateStore(client=redis_client, operation_timeout_seconds=1.0)


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


def test_satisfies_the_port(store: RedisLoginStateStore) -> None:
    port: LoginStateStore = store

    assert port is store


async def test_saved_login_comes_back_whole(store: RedisLoginStateStore) -> None:
    await store.save(STATE, PENDING, TTL)

    assert await store.pop(STATE) == PENDING


async def test_saved_login_can_be_taken_only_once(store: RedisLoginStateStore) -> None:
    await store.save(STATE, PENDING, TTL)
    await store.pop(STATE)

    assert await store.pop(STATE) is None


async def test_parallel_pops_get_the_login_once(store: RedisLoginStateStore) -> None:
    await store.save(STATE, PENDING, TTL)

    results = await asyncio.gather(*(store.pop(STATE) for _ in range(10)))

    assert results.count(PENDING) == 1
    assert results.count(None) == 9


async def test_logins_do_not_mix(store: RedisLoginStateStore) -> None:
    other_state = "O" * 43
    other = PendingLoginDTO("v" * 43, "n" * 43, "/", "c" * 64)
    await store.save(STATE, PENDING, TTL)
    await store.save(other_state, other, TTL)

    assert await store.pop(other_state) == other
    assert await store.pop(STATE) == PENDING


async def test_only_the_hash_of_the_state_reaches_redis(
    store: RedisLoginStateStore, redis_client: Redis
) -> None:
    await store.save(STATE, PENDING, TTL)

    assert await redis_client.keys("*") == ["oauth_state:" + sha256(STATE.encode()).hexdigest()]


async def test_value_is_plain_json_with_readable_text(
    store: RedisLoginStateStore, redis_client: Redis
) -> None:
    await store.save(STATE, PENDING, TTL)

    [key] = await redis_client.keys("*")
    raw = await redis_client.get(key)
    assert isinstance(raw, str)
    assert json.loads(raw) == {
        "code_verifier": "V" * 43,
        "nonce": "N" * 43,
        "next": "/рецепты/42?tab=steps",
        "browser_binding_hash": "b" * 64,
    }
    assert "/рецепты/" in raw


async def test_login_lives_for_the_given_ttl(
    store: RedisLoginStateStore, redis_client: Redis
) -> None:
    await store.save(STATE, PENDING, TTL)

    [key] = await redis_client.keys("*")
    assert 590 <= await redis_client.ttl(key) <= 600


async def test_expired_login_is_gone(store: RedisLoginStateStore, redis_client: Redis) -> None:
    await store.save(STATE, PENDING, TTL)
    [key] = await redis_client.keys("*")
    await redis_client.pexpire(key, 50)
    await asyncio.sleep(0.1)

    assert await store.pop(STATE) is None


async def test_unknown_state_is_nothing(store: RedisLoginStateStore) -> None:
    assert await store.pop("U" * 43) is None


@pytest.mark.parametrize(
    "state", ["", "short", "A" * 42, "A" * 44, "A" * 42 + "!", "A" * 42 + "\n", "А" * 43]
)
async def test_malformed_state_never_reaches_redis(state: str) -> None:
    store = RedisLoginStateStore(
        client=cast(Redis, UntouchableRedis()), operation_timeout_seconds=1
    )

    assert await store.pop(state) is None


async def test_hanging_redis_is_cut_by_operation_timeout(silent_redis: Redis) -> None:
    store = RedisLoginStateStore(client=silent_redis, operation_timeout_seconds=0.3)
    started = time.monotonic()

    with pytest.raises(LoginStateStoreUnavailableError) as caught:
        async with asyncio.timeout(5):
            await store.pop(STATE)

    assert time.monotonic() - started < 1.5
    assert isinstance(caught.value.__cause__, TimeoutError)


async def test_hanging_redis_cuts_save_by_operation_timeout(silent_redis: Redis) -> None:
    store = RedisLoginStateStore(client=silent_redis, operation_timeout_seconds=0.3)

    with pytest.raises(LoginStateStoreUnavailableError):
        async with asyncio.timeout(5):
            await store.save(STATE, PENDING, TTL)


async def test_refused_connection_is_reported_as_unavailable(refusing_redis: Redis) -> None:
    store = RedisLoginStateStore(client=refusing_redis, operation_timeout_seconds=1.0)

    with pytest.raises(LoginStateStoreUnavailableError) as caught:
        async with asyncio.timeout(5):
            await store.save(STATE, PENDING, TTL)

    assert isinstance(caught.value, DependencyUnavailableError)

    with pytest.raises(LoginStateStoreUnavailableError):
        async with asyncio.timeout(5):
            await store.pop(STATE)
