import asyncio
import re
import secrets
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from datetime import timedelta
from hashlib import sha256
from uuid import UUID

from redis.asyncio import ConnectionError as RedisConnectionError
from redis.asyncio import Redis
from redis.asyncio import TimeoutError as RedisTimeoutError

from app.modules.identity.domain.enums import TokenPurpose
from app.modules.identity.infrastructure.exceptions import OneTimeTokenStoreUnavailableError

TOKEN_PATTERN = re.compile(r"[A-Za-z0-9_-]{43}")
KEY_PREFIX = "auth_token:"


class RedisOneTimeTokenStore:
    def __init__(
        self,
        client: Redis,
        operation_timeout_seconds: float,
    ):
        self._client = client
        self._operation_timeout_seconds = operation_timeout_seconds

    @staticmethod
    def _calc_key(purpose: str, token: str) -> str:
        return KEY_PREFIX + purpose + ":" + sha256(token.encode()).hexdigest()

    @asynccontextmanager
    async def _guard(self) -> AsyncGenerator[None]:
        try:
            async with asyncio.timeout(self._operation_timeout_seconds):
                yield
        except (TimeoutError, RedisTimeoutError, RedisConnectionError) as exc:
            raise OneTimeTokenStoreUnavailableError("Token store is unavailable") from exc

    async def issue(self, purpose: TokenPurpose, user_id: UUID, ttl: timedelta) -> str:
        token = secrets.token_urlsafe(32)
        key = self._calc_key(purpose.value, token)
        async with self._guard():
            await self._client.set(key, str(user_id), ex=ttl)
        return token

    async def consume(self, purpose: TokenPurpose, token: str) -> UUID | None:
        if not TOKEN_PATTERN.fullmatch(token):
            return None
        key = self._calc_key(purpose.value, token)
        async with self._guard():
            value = await self._client.getdel(key)
        if value is None:
            return None
        return UUID(str(value))
