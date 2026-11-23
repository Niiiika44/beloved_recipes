import asyncio
import secrets

import argon2

from app.modules.identity.service.dto import PasswordCheckDTO

MAX_CONCURRENT_HASHES = 4


class Argon2PasswordHasher:
    def __init__(self, max_concurrent: int = MAX_CONCURRENT_HASHES):
        self._hasher = argon2.PasswordHasher()
        self._semaphore = asyncio.Semaphore(max_concurrent)
        self._dummy_hash = self._hasher.hash(secrets.token_urlsafe(32))

    async def hash_password(self, password: str) -> str:
        async with self._semaphore:
            return await asyncio.to_thread(self._hasher.hash, password)

    async def verify(self, password_hash: str, password: str) -> PasswordCheckDTO:
        async with self._semaphore:
            return await asyncio.to_thread(self._verify, password_hash, password)

    def _verify(self, password_hash: str, password: str) -> PasswordCheckDTO:
        try:
            matches = self._hasher.verify(password_hash, password)
        except argon2.exceptions.VerificationError, ValueError:
            return PasswordCheckDTO(matches=False, needs_rehash=False)
        return PasswordCheckDTO(
            matches=matches, needs_rehash=self._hasher.check_needs_rehash(password_hash)
        )

    async def verify_dummy(self, password: str) -> None:
        await self.verify(self._dummy_hash, password)
