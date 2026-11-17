import asyncio
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager

from redis.asyncio import ConnectionError as RedisConnectionError
from redis.asyncio import Redis
from redis.asyncio import TimeoutError as RedisTimeoutError

from app.modules.identity.domain.limits import RateLimit
from app.modules.identity.infrastructure.exceptions import RateLimiterUnavailableError

KEY_PREFIX = "rate_limit:"


class RedisRateLimiter:
    def __init__(
        self,
        client: Redis,
        operation_timeout_seconds: float,
    ):
        self._client = client
        self._operation_timeout_seconds = operation_timeout_seconds

    @asynccontextmanager
    async def _guard(self) -> AsyncGenerator[None]:
        try:
            async with asyncio.timeout(self._operation_timeout_seconds):
                yield
        except (TimeoutError, RedisTimeoutError, RedisConnectionError) as exc:
            raise RateLimiterUnavailableError("Rate limiter is unavailable") from exc

    async def hit(self, key: str, rule: RateLimit) -> int | None:
        full_key = KEY_PREFIX + key
        async with self._guard(), self._client.pipeline(transaction=True) as pipe:
            pipe.incr(full_key)
            pipe.expire(full_key, rule.window, nx=True)
            pipe.ttl(full_key)
            results = await pipe.execute()
        count, _, ttl = results
        if int(count) <= rule.limit:
            return None
        return max(1, int(ttl))
