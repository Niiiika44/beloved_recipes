import asyncio
import json
import re
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from dataclasses import asdict
from datetime import timedelta
from hashlib import sha256

from redis.asyncio import ConnectionError as RedisConnectionError
from redis.asyncio import Redis
from redis.asyncio import TimeoutError as RedisTimeoutError

from app.modules.identity.infrastructure.exceptions import LoginStateStoreUnavailableError
from app.modules.identity.service.dto import PendingLoginDTO

STATE_PATTERN = re.compile(r"[A-Za-z0-9_-]{43}")
KEY_PREFIX = "oauth_state:"


class RedisLoginStateStore:
    def __init__(
        self,
        client: Redis,
        operation_timeout_seconds: float,
    ):
        self._client = client
        self._operation_timeout_seconds = operation_timeout_seconds

    @staticmethod
    def _calc_key(state: str) -> str:
        return KEY_PREFIX + sha256(state.encode()).hexdigest()

    @asynccontextmanager
    async def _guard(self) -> AsyncGenerator[None]:
        try:
            async with asyncio.timeout(self._operation_timeout_seconds):
                yield
        except (TimeoutError, RedisTimeoutError, RedisConnectionError) as exc:
            raise LoginStateStoreUnavailableError("Login state store is unavailable") from exc

    async def save(self, state: str, pending: PendingLoginDTO, ttl: timedelta) -> None:
        key = self._calc_key(state)
        value = json.dumps(asdict(pending), ensure_ascii=False)
        async with self._guard():
            await self._client.set(key, value, ex=ttl)

    async def pop(self, state: str) -> PendingLoginDTO | None:
        if not STATE_PATTERN.fullmatch(state):
            return None
        key = self._calc_key(state)
        async with self._guard():
            value = await self._client.getdel(key)
        return self._parse(value)

    @staticmethod
    def _parse(value: bytes | str | None) -> PendingLoginDTO | None:
        if value is None:
            return None
        value_dct = json.loads(value)
        return PendingLoginDTO(
            code_verifier=value_dct["code_verifier"],
            nonce=value_dct["nonce"],
            next=value_dct["next"],
            browser_binding_hash=value_dct["browser_binding_hash"],
        )
