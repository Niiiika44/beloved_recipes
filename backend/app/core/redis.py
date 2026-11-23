from functools import lru_cache

from redis.asyncio import BlockingConnectionPool, Redis

from app.core.config import get_settings


@lru_cache(maxsize=1)
def get_redis() -> Redis:
    settings = get_settings()
    pool = BlockingConnectionPool.from_url(
        settings.redis.dsn,
        max_connections=settings.redis.max_connections,
        timeout=settings.redis.pool_timeout_seconds,
        decode_responses=True,
        socket_timeout=settings.redis.socket_timeout_seconds,
        socket_connect_timeout=settings.redis.socket_connect_timeout_seconds,
        health_check_interval=settings.redis.health_check_interval,
    )
    return Redis.from_pool(pool)


async def close_redis() -> None:
    r = get_redis()
    await r.aclose()
    get_redis.cache_clear()
