import asyncio
import re
import socket
import time
import uuid
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from typing import Any, cast

import pytest
from redis.asyncio import Redis
from redis.asyncio.retry import Retry
from redis.backoff import NoBackoff
from redis.exceptions import ConnectionError as RedisConnectionError
from redis.exceptions import RedisError, ResponseError

from app.core.exceptions import DependencyUnavailableError
from app.core.redis import close_redis, get_redis
from app.modules.identity.infrastructure.exceptions import SessionStoreUnavailableError
from app.modules.identity.infrastructure.redis_session_store import RedisSessionStore

IDLE = 3_600
ABSOLUTE = 86_400
TOKEN_PATTERN = re.compile(r"[A-Za-z0-9_-]{43}")
STARTED_AT = datetime(2026, 10, 14, 12, 0, 0, 123456, tzinfo=UTC)


class Clock:
    def __init__(self, moment: datetime) -> None:
        self.moment = moment

    def __call__(self) -> datetime:
        return self.moment

    def advance(self, delta: timedelta) -> None:
        self.moment += delta


class UntouchableRedis:
    def __getattr__(self, name: str) -> Any:
        raise AssertionError(f"Redis must not be called, got {name}")


def _key(token: str) -> str:
    return "session:" + sha256(token.encode()).hexdigest()


def _store(client: Redis, clock: Clock, timeout: float = 1.0) -> RedisSessionStore:
    return RedisSessionStore(
        client=client,
        idle_ttl_seconds=IDLE,
        absolute_ttl_seconds=ABSOLUTE,
        operation_timeout_seconds=timeout,
        now=clock,
    )


@pytest.fixture
async def redis_client(_point_redis_at_container: None) -> AsyncIterator[Redis]:
    get_redis.cache_clear()
    client = get_redis()
    await client.flushdb()

    yield client

    await close_redis()


@pytest.fixture
def clock() -> Clock:
    return Clock(STARTED_AT)


@pytest.fixture
def store(redis_client: Redis, clock: Clock) -> RedisSessionStore:
    return _store(redis_client, clock)


@pytest.fixture
def offline_store(clock: Clock) -> RedisSessionStore:
    return _store(cast(Redis, UntouchableRedis()), clock)


async def _all_keys_and_values(client: Redis) -> list[str]:
    found: list[str] = []
    async for key in client.scan_iter():
        found.append(key)
        value = await client.get(key)
        if value is not None:
            found.append(value if isinstance(value, str) else value.decode())
    return found


async def test_create_returns_url_safe_token_of_43_chars(store: RedisSessionStore) -> None:
    token = await store.create(uuid.uuid4())

    assert isinstance(token, str)
    assert TOKEN_PATTERN.fullmatch(token)


async def test_tokens_are_unique(store: RedisSessionStore) -> None:
    user_id = uuid.uuid4()

    tokens = {await store.create(user_id) for _ in range(20)}

    assert len(tokens) == 20


async def test_create_stores_exactly_one_key_named_by_token_hash(
    store: RedisSessionStore, redis_client: Redis
) -> None:
    before = {key async for key in redis_client.scan_iter()}

    token = await store.create(uuid.uuid4())

    after = {key async for key in redis_client.scan_iter()}
    assert after - before == {_key(token)}


async def test_raw_token_never_reaches_redis(store: RedisSessionStore, redis_client: Redis) -> None:
    token = await store.create(uuid.uuid4())

    stored = await _all_keys_and_values(redis_client)

    assert stored
    assert all(token not in item for item in stored)


async def test_resolve_returns_session_of_created_user(store: RedisSessionStore) -> None:
    user_id = uuid.uuid4()
    token = await store.create(user_id)

    session = await store.resolve(token)

    assert session is not None
    assert isinstance(session.user_id, uuid.UUID)
    assert session.user_id == user_id


async def test_resolve_reports_creation_time_in_utc(store: RedisSessionStore) -> None:
    token = await store.create(uuid.uuid4())

    session = await store.resolve(token)

    assert session is not None
    assert isinstance(session.created_at, datetime)
    assert session.created_at == STARTED_AT
    assert session.created_at.utcoffset() == timedelta(0)


async def test_resolve_unknown_token_returns_none(store: RedisSessionStore) -> None:
    await store.create(uuid.uuid4())

    assert await store.resolve("A" * 43) is None


async def test_token_hash_cannot_be_used_as_token(store: RedisSessionStore) -> None:
    token = await store.create(uuid.uuid4())

    assert await store.resolve(sha256(token.encode()).hexdigest()) is None
    assert await store.resolve(_key(token)) is None


@pytest.mark.parametrize(
    "token",
    ["", "A" * 42, "A" * 44, "A" * 42 + "!", "A" * 42 + " ", "A" * 42 + "=", "Б" * 43],
    ids=["empty", "short", "long", "bang", "space", "padding", "non-ascii"],
)
async def test_resolve_rejects_malformed_token_without_calling_redis(
    offline_store: RedisSessionStore, token: str
) -> None:
    assert await offline_store.resolve(token) is None


@pytest.mark.parametrize("token", ["", "A" * 42, "A" * 42 + "!"], ids=["empty", "short", "bang"])
async def test_revoke_ignores_malformed_token_without_calling_redis(
    offline_store: RedisSessionStore, token: str
) -> None:
    await offline_store.revoke(token)


async def test_revoke_deletes_session(store: RedisSessionStore, redis_client: Redis) -> None:
    token = await store.create(uuid.uuid4())

    await store.revoke(token)

    assert await redis_client.exists(_key(token)) == 0
    assert await store.resolve(token) is None


async def test_revoke_is_idempotent(store: RedisSessionStore) -> None:
    token = await store.create(uuid.uuid4())
    await store.revoke(token)

    await store.revoke(token)

    assert await store.resolve(token) is None


async def test_revoke_leaves_other_sessions_alone(store: RedisSessionStore) -> None:
    user_id = uuid.uuid4()
    kept = await store.create(user_id)
    dropped = await store.create(user_id)

    await store.revoke(dropped)

    session = await store.resolve(kept)
    assert session is not None
    assert session.user_id == user_id


async def test_new_session_lives_for_idle_ttl(
    store: RedisSessionStore, redis_client: Redis
) -> None:
    token = await store.create(uuid.uuid4())

    ttl = await redis_client.ttl(_key(token))

    assert IDLE - 5 < ttl <= IDLE


async def test_resolve_extends_session_to_full_idle_ttl(
    store: RedisSessionStore, redis_client: Redis
) -> None:
    token = await store.create(uuid.uuid4())
    await redis_client.expire(_key(token), 100)

    await store.resolve(token)

    ttl = await redis_client.ttl(_key(token))
    assert IDLE - 5 < ttl <= IDLE


async def test_session_past_absolute_lifetime_is_gone(
    store: RedisSessionStore, redis_client: Redis, clock: Clock
) -> None:
    token = await store.create(uuid.uuid4())
    clock.advance(timedelta(seconds=ABSOLUTE + 1))

    assert await store.resolve(token) is None
    assert await redis_client.exists(_key(token)) == 0


async def test_session_just_before_absolute_lifetime_is_alive(
    store: RedisSessionStore, clock: Clock
) -> None:
    user_id = uuid.uuid4()
    token = await store.create(user_id)
    clock.advance(timedelta(seconds=ABSOLUTE - 1))

    session = await store.resolve(token)

    assert session is not None
    assert session.user_id == user_id


async def test_session_exactly_at_absolute_lifetime_is_alive(
    store: RedisSessionStore, clock: Clock
) -> None:
    token = await store.create(uuid.uuid4())
    clock.advance(timedelta(seconds=ABSOLUTE))

    assert await store.resolve(token) is not None


async def test_expired_session_stays_gone_when_clock_rolls_back(
    store: RedisSessionStore, clock: Clock
) -> None:
    token = await store.create(uuid.uuid4())
    clock.advance(timedelta(seconds=ABSOLUTE + 1))
    await store.resolve(token)
    clock.advance(timedelta(seconds=-(ABSOLUTE + 1)))

    assert await store.resolve(token) is None


async def test_absolute_expiry_of_one_session_spares_newer_ones(
    store: RedisSessionStore, clock: Clock
) -> None:
    user_id = uuid.uuid4()
    old = await store.create(user_id)
    clock.advance(timedelta(seconds=ABSOLUTE - 10))
    fresh = await store.create(user_id)
    clock.advance(timedelta(seconds=20))

    assert await store.resolve(old) is None
    assert await store.resolve(fresh) is not None


OPERATIONS = ["create", "resolve", "revoke"]
WELL_FORMED = "A" * 43


async def _call(store: RedisSessionStore, operation: str) -> None:
    if operation == "create":
        await store.create(uuid.uuid4())
    elif operation == "resolve":
        await store.resolve(WELL_FORMED)
    else:
        await store.revoke(WELL_FORMED)


def _free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port: int = probe.getsockname()[1]
    return port


@pytest.fixture
async def refusing_redis() -> AsyncIterator[Redis]:
    client = Redis(
        host="127.0.0.1",
        port=_free_port(),
        decode_responses=True,
        socket_connect_timeout=5,
        socket_timeout=5,
    )

    yield client

    await client.aclose()


@pytest.fixture
async def refusing_redis_without_retries() -> AsyncIterator[Redis]:
    client = Redis(
        host="127.0.0.1",
        port=_free_port(),
        decode_responses=True,
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
    client = Redis(
        host="127.0.0.1",
        port=port,
        decode_responses=True,
        socket_connect_timeout=30,
        socket_timeout=30,
    )

    yield client

    await client.aclose()
    for writer in writers:
        writer.close()
    server.close()
    await server.wait_closed()


@pytest.mark.parametrize("operation", OPERATIONS)
async def test_unreachable_redis_is_reported_as_unavailable(
    refusing_redis: Redis, clock: Clock, operation: str
) -> None:
    store = _store(refusing_redis, clock)
    started = time.monotonic()

    with pytest.raises(DependencyUnavailableError) as caught:
        async with asyncio.timeout(5):
            await _call(store, operation)

    assert time.monotonic() - started < 3
    assert isinstance(caught.value.__cause__, (TimeoutError, RedisError))


@pytest.mark.parametrize("operation", OPERATIONS)
async def test_hanging_redis_is_cut_by_operation_timeout(
    silent_redis: Redis, clock: Clock, operation: str
) -> None:
    store = _store(silent_redis, clock, timeout=0.3)
    started = time.monotonic()

    with pytest.raises(DependencyUnavailableError) as caught:
        async with asyncio.timeout(5):
            await _call(store, operation)

    assert time.monotonic() - started < 1.5
    assert isinstance(caught.value.__cause__, TimeoutError)


@pytest.mark.parametrize("operation", OPERATIONS)
async def test_refused_connection_is_reported_as_unavailable(
    refusing_redis_without_retries: Redis, clock: Clock, operation: str
) -> None:
    store = _store(refusing_redis_without_retries, clock)

    with pytest.raises(DependencyUnavailableError) as caught:
        async with asyncio.timeout(5):
            await _call(store, operation)

    assert isinstance(caught.value.__cause__, RedisConnectionError)


async def test_unavailability_message_hides_connection_details(
    refusing_redis_without_retries: Redis, clock: Clock
) -> None:
    port = refusing_redis_without_retries.connection_pool.connection_kwargs["port"]
    store = _store(refusing_redis_without_retries, clock)

    with pytest.raises(DependencyUnavailableError) as caught:
        async with asyncio.timeout(5):
            await store.resolve(WELL_FORMED)

    assert caught.value.message
    assert str(port) not in caught.value.message
    assert "127.0.0.1" not in caught.value.message


async def test_timeout_still_produces_a_meaningful_message(
    silent_redis: Redis, clock: Clock
) -> None:
    store = _store(silent_redis, clock, timeout=0.3)

    with pytest.raises(DependencyUnavailableError) as caught:
        async with asyncio.timeout(5):
            await store.resolve(WELL_FORMED)

    assert caught.value.message


async def test_unavailability_names_the_session_store(
    refusing_redis_without_retries: Redis, clock: Clock
) -> None:
    store = _store(refusing_redis_without_retries, clock)

    with pytest.raises(SessionStoreUnavailableError):
        async with asyncio.timeout(5):
            await store.resolve(WELL_FORMED)


async def test_corrupted_entry_is_not_disguised_as_unavailability(
    store: RedisSessionStore, redis_client: Redis
) -> None:
    token = await store.create(uuid.uuid4())
    await redis_client.delete(_key(token))
    await redis_client.hset(_key(token), mapping={"user_id": "x"})

    with pytest.raises(ResponseError):
        await store.resolve(token)
