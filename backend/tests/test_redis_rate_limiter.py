import asyncio
import socket
import time
from collections.abc import AsyncIterator
from datetime import timedelta

import pytest
from redis.asyncio import Redis
from redis.asyncio.retry import Retry
from redis.backoff import NoBackoff
from redis.exceptions import ConnectionError as RedisConnectionError

from app.core.exceptions import DependencyUnavailableError
from app.core.redis import close_redis, get_redis
from app.modules.identity.domain.limits import RateLimit
from app.modules.identity.infrastructure.exceptions import RateLimiterUnavailableError
from app.modules.identity.infrastructure.redis_rate_limiter import RedisRateLimiter
from app.modules.identity.service.ports import RateLimiter

THREE_PER_MINUTE = RateLimit(limit=3, window=timedelta(minutes=1))
KEY = "nickname_change:cook"


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
def limiter(redis_client: Redis) -> RedisRateLimiter:
    return RedisRateLimiter(client=redis_client, operation_timeout_seconds=1.0)


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


async def _hits(limiter: RedisRateLimiter, times: int, key: str = KEY) -> list[int | None]:
    return [await limiter.hit(key, THREE_PER_MINUTE) for _ in range(times)]


def test_satisfies_the_port(limiter: RedisRateLimiter) -> None:
    port: RateLimiter = limiter

    assert port is limiter


async def test_hits_within_the_limit_pass(limiter: RedisRateLimiter) -> None:
    assert await _hits(limiter, 3) == [None, None, None]


async def test_hit_over_the_limit_reports_seconds_to_wait(limiter: RedisRateLimiter) -> None:
    await _hits(limiter, 3)

    retry_after = await limiter.hit(KEY, THREE_PER_MINUTE)

    assert retry_after is not None
    assert 1 <= retry_after <= 60


async def test_every_hit_over_the_limit_is_refused(limiter: RedisRateLimiter) -> None:
    results = await _hits(limiter, 6)

    assert results[:3] == [None, None, None]
    assert all(result is not None for result in results[3:])


async def test_counter_lives_under_its_own_prefix(
    limiter: RedisRateLimiter, redis_client: Redis
) -> None:
    await _hits(limiter, 2)

    assert await redis_client.keys("*") == ["rate_limit:" + KEY]
    assert await redis_client.get("rate_limit:" + KEY) == "2"


async def test_window_starts_with_the_first_hit(
    limiter: RedisRateLimiter, redis_client: Redis
) -> None:
    await limiter.hit(KEY, THREE_PER_MINUTE)

    assert 59 <= await redis_client.ttl("rate_limit:" + KEY) <= 60


async def test_later_hits_do_not_extend_the_window(
    limiter: RedisRateLimiter, redis_client: Redis
) -> None:
    await limiter.hit(KEY, THREE_PER_MINUTE)
    await redis_client.expire("rate_limit:" + KEY, 30)

    await _hits(limiter, 4)

    assert await redis_client.ttl("rate_limit:" + KEY) <= 30


async def test_wait_matches_what_is_left_of_the_window(
    limiter: RedisRateLimiter, redis_client: Redis
) -> None:
    await _hits(limiter, 3)
    await redis_client.expire("rate_limit:" + KEY, 17)

    assert await limiter.hit(KEY, THREE_PER_MINUTE) == 17


async def test_counter_resets_when_the_window_ends(
    limiter: RedisRateLimiter, redis_client: Redis
) -> None:
    await _hits(limiter, 4)
    await redis_client.pexpire("rate_limit:" + KEY, 50)
    await asyncio.sleep(0.1)

    assert await _hits(limiter, 3) == [None, None, None]


async def test_counter_without_expiry_gets_one(
    limiter: RedisRateLimiter, redis_client: Redis
) -> None:
    await redis_client.set("rate_limit:" + KEY, 1)

    await limiter.hit(KEY, THREE_PER_MINUTE)

    assert 59 <= await redis_client.ttl("rate_limit:" + KEY) <= 60


async def test_keys_are_counted_separately(limiter: RedisRateLimiter) -> None:
    await _hits(limiter, 4, key="nickname_change:anna")

    assert await _hits(limiter, 3, key="nickname_change:boris") == [None, None, None]


async def test_rules_limit_independently(limiter: RedisRateLimiter) -> None:
    one_per_minute = RateLimit(limit=1, window=timedelta(minutes=1))

    assert await limiter.hit(KEY, one_per_minute) is None
    assert await limiter.hit(KEY, one_per_minute) is not None


async def test_refused_connection_is_reported_as_unavailable(refusing_redis: Redis) -> None:
    limiter = RedisRateLimiter(client=refusing_redis, operation_timeout_seconds=1.0)

    with pytest.raises(RateLimiterUnavailableError) as caught:
        async with asyncio.timeout(5):
            await limiter.hit(KEY, THREE_PER_MINUTE)

    assert isinstance(caught.value, DependencyUnavailableError)
    assert isinstance(caught.value.__cause__, (RedisConnectionError, TimeoutError))


async def test_hanging_redis_is_cut_by_operation_timeout(silent_redis: Redis) -> None:
    limiter = RedisRateLimiter(client=silent_redis, operation_timeout_seconds=0.3)
    started = time.monotonic()

    with pytest.raises(RateLimiterUnavailableError) as caught:
        async with asyncio.timeout(5):
            await limiter.hit(KEY, THREE_PER_MINUTE)

    assert time.monotonic() - started < 1.5
    assert isinstance(caught.value.__cause__, TimeoutError)


async def test_unavailability_message_hides_connection_details(refusing_redis: Redis) -> None:
    port = refusing_redis.connection_pool.connection_kwargs["port"]
    limiter = RedisRateLimiter(client=refusing_redis, operation_timeout_seconds=1.0)

    with pytest.raises(RateLimiterUnavailableError) as caught:
        async with asyncio.timeout(5):
            await limiter.hit(KEY, THREE_PER_MINUTE)

    assert caught.value.message
    assert str(port) not in caught.value.message
    assert "127.0.0.1" not in caught.value.message
