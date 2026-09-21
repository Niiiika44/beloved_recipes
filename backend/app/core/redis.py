from functools import lru_cache

from redis.asyncio import Redis

from app.core.config import get_settings


@lru_cache(maxsize=1)
def get_redis() -> Redis:
    settings = get_settings()
    client = Redis.from_url(
        settings.redis.dsn,
        decode_responses=True,
        socket_timeout=settings.redis.socket_timeout_seconds,
        socket_connect_timeout=settings.redis.socket_connect_timeout_seconds,
        max_connections=settings.redis.max_connections,
        health_check_interval=settings.redis.health_check_interval,
    )
    return client


async def close_redis() -> None:
    r = get_redis()
    await r.aclose()
    get_redis.cache_clear()
