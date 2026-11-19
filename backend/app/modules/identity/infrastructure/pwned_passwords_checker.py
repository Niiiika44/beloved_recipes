import asyncio
import hashlib

import httpx

PWNED_RANGE_URL = "https://api.pwnedpasswords.com/range/"
PWNED_TIMEOUT_SECONDS = 1.0
PREFIX_LENGTH = 5


def _occurrences(suffix: str, body: str) -> int | None:
    for line in body.splitlines():
        candidate, _, count = line.partition(":")
        if candidate == suffix:
            return int(count) if count.strip().isdigit() else None
    return 0


class PwnedPasswordsChecker:
    def __init__(
        self,
        timeout_seconds: float = PWNED_TIMEOUT_SECONDS,
        transport: httpx.AsyncBaseTransport | None = None,
    ):
        self._timeout_seconds = timeout_seconds
        self._transport = transport

    async def is_breached(self, password: str) -> bool | None:
        digest = hashlib.sha1(password.encode(), usedforsecurity=False).hexdigest().upper()
        prefix, suffix = digest[:PREFIX_LENGTH], digest[PREFIX_LENGTH:]
        try:
            async with (
                asyncio.timeout(self._timeout_seconds),
                httpx.AsyncClient(transport=self._transport) as client,
            ):
                response = await client.get(
                    PWNED_RANGE_URL + prefix, headers={"Add-Padding": "true"}
                )
        except TimeoutError, httpx.HTTPError:
            return None
        if response.status_code != httpx.codes.OK:
            return None
        occurrences = _occurrences(suffix, response.text)
        if occurrences is None:
            return None
        return occurrences > 0
