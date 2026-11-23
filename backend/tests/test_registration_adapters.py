import asyncio
import hashlib
import threading
import time

import argon2
import httpx
import pytest
import structlog

from app.modules.identity.infrastructure.argon2_password_hasher import (
    MAX_CONCURRENT_HASHES,
    Argon2PasswordHasher,
)
from app.modules.identity.infrastructure.pwned_passwords_checker import (
    PWNED_TIMEOUT_SECONDS,
    PwnedPasswordsChecker,
)
from app.modules.identity.infrastructure.structlog_security_events import (
    StructlogSecurityEvents,
)
from app.modules.identity.service.ports import (
    BreachedPasswordChecker,
    PasswordHasher,
    SecurityEvents,
)

PASSWORD = "correct horse battery staple"
DIGEST = hashlib.sha1(PASSWORD.encode(), usedforsecurity=False).hexdigest().upper()
PREFIX, SUFFIX = DIGEST[:5], DIGEST[5:]
OTHER_SUFFIX = "0" * 35


class SlowHash:
    def __init__(self) -> None:
        self.active = 0
        self.peak = 0
        self.threads: set[int] = set()
        self._lock = threading.Lock()

    def __call__(self, password: str | bytes) -> str:
        with self._lock:
            self.active += 1
            self.peak = max(self.peak, self.active)
            self.threads.add(threading.get_ident())
        time.sleep(0.05)
        with self._lock:
            self.active -= 1
        return "$argon2id$slow"


@pytest.fixture
def slow_hash(monkeypatch: pytest.MonkeyPatch) -> SlowHash:
    slow = SlowHash()
    monkeypatch.setattr(argon2.PasswordHasher, "hash", slow)
    return slow


class Recorder:
    def __init__(self, status: int = 200, body: str = "") -> None:
        self.status = status
        self.body = body
        self.requests: list[httpx.Request] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        return httpx.Response(self.status, text=self.body)


def _checker(handler: Recorder) -> PwnedPasswordsChecker:
    return PwnedPasswordsChecker(transport=httpx.MockTransport(handler))


def test_adapters_satisfy_ports() -> None:
    hasher: PasswordHasher = Argon2PasswordHasher()
    checker: BreachedPasswordChecker = PwnedPasswordsChecker()
    events: SecurityEvents = StructlogSecurityEvents()

    assert isinstance(hasher, Argon2PasswordHasher)
    assert isinstance(checker, PwnedPasswordsChecker)
    assert isinstance(events, StructlogSecurityEvents)


async def test_hash_is_argon2id_with_library_defaults() -> None:
    password_hash = await Argon2PasswordHasher().hash_password(PASSWORD)

    assert password_hash.startswith("$argon2id$v=19$m=65536,t=3,p=4$")
    assert argon2.PasswordHasher().verify(password_hash, PASSWORD)


async def test_hash_is_salted() -> None:
    hasher = Argon2PasswordHasher()

    first = await hasher.hash_password(PASSWORD)
    second = await hasher.hash_password(PASSWORD)

    assert first != second
    assert PASSWORD not in first


def test_hashing_concurrency_defaults_to_four() -> None:
    assert MAX_CONCURRENT_HASHES == 4


async def test_no_more_than_four_hashes_run_at_once(slow_hash: SlowHash) -> None:
    hasher = Argon2PasswordHasher()

    await asyncio.gather(*(hasher.hash_password(PASSWORD) for _ in range(12)))

    assert slow_hash.peak == 4


@pytest.mark.parametrize("limit", [1, 2])
async def test_concurrency_limit_is_configurable(slow_hash: SlowHash, limit: int) -> None:
    hasher = Argon2PasswordHasher(max_concurrent=limit)

    await asyncio.gather(*(hasher.hash_password(PASSWORD) for _ in range(6)))

    assert slow_hash.peak == limit


async def test_hashing_runs_off_the_event_loop(slow_hash: SlowHash) -> None:
    hasher = Argon2PasswordHasher()
    slow_hash.threads.clear()
    ticks = 0

    async def ticker() -> None:
        nonlocal ticks
        for _ in range(8):
            await asyncio.sleep(0.01)
            ticks += 1

    await asyncio.gather(ticker(), *(hasher.hash_password(PASSWORD) for _ in range(8)))

    assert threading.get_ident() not in slow_hash.threads
    assert ticks == 8


async def test_checker_sends_only_the_hash_prefix() -> None:
    handler = Recorder(body=f"{OTHER_SUFFIX}:3\r\n")

    await _checker(handler).is_breached(PASSWORD)

    [request] = handler.requests
    assert request.method == "GET"
    assert str(request.url) == f"https://api.pwnedpasswords.com/range/{PREFIX}"
    assert request.headers["Add-Padding"] == "true"
    sent = str(request.url) + str(dict(request.headers)) + request.content.decode()
    assert SUFFIX not in sent
    assert PASSWORD not in sent


async def test_password_found_with_count_is_breached() -> None:
    handler = Recorder(body=f"{OTHER_SUFFIX}:1\r\n{SUFFIX}:42\r\n")

    assert await _checker(handler).is_breached(PASSWORD) is True


async def test_padding_line_with_zero_count_is_not_a_breach() -> None:
    handler = Recorder(body=f"{SUFFIX}:0\r\n{OTHER_SUFFIX}:7\r\n")

    assert await _checker(handler).is_breached(PASSWORD) is False


@pytest.mark.parametrize(
    "body",
    ["", f"{OTHER_SUFFIX}:5\r\n", f"{SUFFIX[:-1]}:5\r\n", f"X{SUFFIX}:5\r\n"],
    ids=["empty", "other_suffix", "shorter_suffix", "longer_suffix"],
)
async def test_absent_password_is_not_breached(body: str) -> None:
    assert await _checker(Recorder(body=body)).is_breached(PASSWORD) is False


@pytest.mark.parametrize("status", [400, 429, 500, 503])
async def test_unexpected_status_means_unknown(status: int) -> None:
    handler = Recorder(status=status, body=f"{SUFFIX}:42\r\n")

    assert await _checker(handler).is_breached(PASSWORD) is None


async def test_unreadable_count_means_unknown() -> None:
    handler = Recorder(body=f"{SUFFIX}:many\r\n")

    assert await _checker(handler).is_breached(PASSWORD) is None


async def test_network_failure_means_unknown() -> None:
    def refuse(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused", request=request)

    checker = PwnedPasswordsChecker(transport=httpx.MockTransport(refuse))

    assert await checker.is_breached(PASSWORD) is None


async def test_slow_service_is_cut_by_the_timeout() -> None:
    async def hang(request: httpx.Request) -> httpx.Response:
        await asyncio.sleep(5)
        return httpx.Response(200, text=f"{SUFFIX}:42\r\n")

    checker = PwnedPasswordsChecker(timeout_seconds=0.2, transport=httpx.MockTransport(hang))
    started = time.monotonic()

    result = await checker.is_breached(PASSWORD)

    assert result is None
    assert time.monotonic() - started < 1


def test_timeout_defaults_to_one_second() -> None:
    assert PWNED_TIMEOUT_SECONDS == 1.0


def test_rate_limit_event_names_action_and_scope_only() -> None:
    with structlog.testing.capture_logs() as records:
        StructlogSecurityEvents().rate_limited("registration", "email")

    assert records == [
        {
            "event": "security.rate_limited",
            "action": "registration",
            "scope": "email",
            "log_level": "warning",
        }
    ]


def test_breach_check_unavailability_is_an_event() -> None:
    with structlog.testing.capture_logs() as records:
        StructlogSecurityEvents().breach_check_unavailable()

    assert records == [{"event": "security.breach_check_unavailable", "log_level": "warning"}]
