import json
import re
import secrets
from collections.abc import Callable
from datetime import datetime, timedelta
from hashlib import sha256
from uuid import UUID

from redis.asyncio import Redis

from app.modules.identity.service.dto import SessionDTO

TOKEN_PATTERN = re.compile(r"[A-Za-z0-9_-]{43}")
KEY_PREFIX = "session:"


class RedisSessionStore:
    def __init__(
        self,
        client: Redis,
        idle_ttl_seconds: int,
        absolute_ttl_seconds: int,
        operation_timeout_seconds: float,
        now: Callable[[], datetime],
    ):
        self._client = client
        self._idle_ttl_seconds = idle_ttl_seconds
        self._absolute_ttl_seconds = absolute_ttl_seconds
        self._operation_timeout_seconds = operation_timeout_seconds
        self._now = now

    @staticmethod
    def _calc_key(token: str) -> str:
        return KEY_PREFIX + sha256(token.encode()).hexdigest()

    async def create(self, user_id: UUID) -> str:
        token = secrets.token_urlsafe(32)
        key = self._calc_key(token)
        value = {"user_id": str(user_id), "created_at": self._now().isoformat()}
        await self._client.set(key, json.dumps(value), ex=self._idle_ttl_seconds)
        return token

    async def resolve(self, token: str) -> SessionDTO | None:
        if not TOKEN_PATTERN.fullmatch(token):
            return None
        key = self._calc_key(token)
        value = await self._client.getex(key, ex=self._idle_ttl_seconds)
        if value is None:
            return None
        value_dct = json.loads(value)
        created_at = datetime.fromisoformat(value_dct["created_at"])
        if self._now() - created_at > timedelta(seconds=self._absolute_ttl_seconds):
            await self.revoke(token)
            return None
        return SessionDTO(
            user_id=UUID(value_dct["user_id"]),
            created_at=created_at,
        )

    async def revoke(self, token: str) -> None:
        if not TOKEN_PATTERN.fullmatch(token):
            return
        key = self._calc_key(token)
        await self._client.delete(key)
