import re
import uuid
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from typing import Any, cast

import pytest
from redis.asyncio import Redis

from app.core.redis import close_redis, get_redis
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


def _store(client: Redis, clock: Clock) -> RedisSessionStore:
    return RedisSessionStore(
        client=client,
        idle_ttl_seconds=IDLE,
        absolute_ttl_seconds=ABSOLUTE,
        operation_timeout_seconds=1.0,
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
