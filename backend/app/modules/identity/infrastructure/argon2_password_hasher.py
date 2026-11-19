import asyncio

import argon2

MAX_CONCURRENT_HASHES = 4


class Argon2PasswordHasher:
    def __init__(self, max_concurrent: int = MAX_CONCURRENT_HASHES):
        self._hasher = argon2.PasswordHasher()
        self._semaphore = asyncio.Semaphore(max_concurrent)

    async def hash_password(self, password: str) -> str:
        async with self._semaphore:
            return await asyncio.to_thread(self._hasher.hash, password)
