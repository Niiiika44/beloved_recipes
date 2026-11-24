import asyncio
import json
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
from app.modules.identity.service.dto import OneTimeTokenDTO

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

    async def issue(
        self, purpose: TokenPurpose, user_id: UUID, credentials_version: int, ttl: timedelta
    ) -> str:
        token = secrets.token_urlsafe(32)
        key = self._calc_key(purpose.value, token)
        value = {"user_id": str(user_id), "credentials_version": credentials_version}
        async with self._guard():
            await self._client.set(key, json.dumps(value), ex=ttl)
        return token

    async def consume(self, purpose: TokenPurpose, token: str) -> OneTimeTokenDTO | None:
        if not TOKEN_PATTERN.fullmatch(token):
            return None
        key = self._calc_key(purpose.value, token)
        async with self._guard():
            value = await self._client.getdel(key)
        return self._parse(value)

    async def peek(self, purpose: TokenPurpose, token: str) -> OneTimeTokenDTO | None:
        if not TOKEN_PATTERN.fullmatch(token):
            return None
        key = self._calc_key(purpose.value, token)
        async with self._guard():
            value = await self._client.get(key)
        return self._parse(value)

    @staticmethod
    def _parse(value: bytes | str | None) -> OneTimeTokenDTO | None:
        if value is None:
            return None
        value_dct = json.loads(value)
        return OneTimeTokenDTO(
            user_id=UUID(value_dct["user_id"]),
            credentials_version=int(value_dct["credentials_version"]),
        )
