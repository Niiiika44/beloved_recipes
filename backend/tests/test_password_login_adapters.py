import asyncio
import threading
import time
import uuid

import argon2
import pytest
import structlog

from app.modules.identity.domain.enums import LoginMethod
from app.modules.identity.infrastructure.argon2_password_hasher import Argon2PasswordHasher
from app.modules.identity.infrastructure.structlog_security_events import (
    StructlogSecurityEvents,
)
from app.modules.identity.service.dto import PasswordCheckDTO

PASSWORD = "correct horse battery staple"
CURRENT_PARAMETERS = argon2.extract_parameters(argon2.PasswordHasher().hash("probe"))


@pytest.fixture(scope="module")
def stored_hash() -> str:
    return argon2.PasswordHasher().hash(PASSWORD)


@pytest.fixture(scope="module")
def outdated_hash() -> str:
    return argon2.PasswordHasher(time_cost=1, memory_cost=8192).hash(PASSWORD)


class RecordingVerify:
    def __init__(self, delay: float = 0.0) -> None:
        self.delay = delay
        self.hashes: list[str] = []
        self.threads: set[int] = set()
        self.active = 0
        self.peak = 0
        self._lock = threading.Lock()
        self._real = argon2.PasswordHasher.verify

    def __call__(self, password_hash: str | bytes, password: str | bytes) -> bool:
        with self._lock:
            self.hashes.append(str(password_hash))
            self.threads.add(threading.get_ident())
            self.active += 1
            self.peak = max(self.peak, self.active)
        try:
            time.sleep(self.delay)
            return self._real(argon2.PasswordHasher(), password_hash, password)
        finally:
            with self._lock:
                self.active -= 1


@pytest.fixture
def recorded(monkeypatch: pytest.MonkeyPatch) -> RecordingVerify:
    recorder = RecordingVerify()
    monkeypatch.setattr(argon2.PasswordHasher, "verify", recorder)
    return recorder


async def test_right_password_matches(stored_hash: str) -> None:
    check = await Argon2PasswordHasher().verify(stored_hash, PASSWORD)

    assert check == PasswordCheckDTO(matches=True, needs_rehash=False)


async def test_wrong_password_does_not_match(stored_hash: str) -> None:
    check = await Argon2PasswordHasher().verify(stored_hash, "correct horse battery stapler")

    assert check == PasswordCheckDTO(matches=False, needs_rehash=False)


async def test_hash_with_outdated_parameters_asks_for_rehash(outdated_hash: str) -> None:
    check = await Argon2PasswordHasher().verify(outdated_hash, PASSWORD)

    assert check == PasswordCheckDTO(matches=True, needs_rehash=True)


async def test_wrong_password_against_outdated_hash_asks_for_nothing(outdated_hash: str) -> None:
    check = await Argon2PasswordHasher().verify(outdated_hash, "another passphrase")

    assert check == PasswordCheckDTO(matches=False, needs_rehash=False)


@pytest.mark.parametrize(
    "corrupted",
    ["", "garbage", "$argon2id$v=19$m=65536,t=3,p=4$broken", "мусор", "$2b$12$" + "a" * 53],
    ids=["empty", "ascii", "truncated", "non_ascii", "bcrypt"],
)
async def test_corrupted_hash_does_not_match(corrupted: str) -> None:
    check = await Argon2PasswordHasher().verify(corrupted, PASSWORD)

    assert check == PasswordCheckDTO(matches=False, needs_rehash=False)


async def test_verification_runs_off_the_event_loop(
    stored_hash: str, recorded: RecordingVerify
) -> None:
    await Argon2PasswordHasher().verify(stored_hash, PASSWORD)

    assert recorded.threads
    assert threading.get_ident() not in recorded.threads


async def test_dummy_check_runs_a_real_argon2_verification(recorded: RecordingVerify) -> None:
    await Argon2PasswordHasher().verify_dummy(PASSWORD)

    [dummy] = recorded.hashes
    assert argon2.extract_parameters(dummy) == CURRENT_PARAMETERS
    assert threading.get_ident() not in recorded.threads


async def test_dummy_hash_is_computed_once_per_hasher(recorded: RecordingVerify) -> None:
    hasher = Argon2PasswordHasher()

    await hasher.verify_dummy(PASSWORD)
    await hasher.verify_dummy("another passphrase")

    first, second = recorded.hashes
    assert first == second


async def test_dummy_check_never_matches_the_password_it_was_given(
    recorded: RecordingVerify,
) -> None:
    hasher = Argon2PasswordHasher()

    await hasher.verify_dummy(PASSWORD)

    [dummy] = recorded.hashes
    check = await hasher.verify(dummy, PASSWORD)
    assert check.matches is False


async def test_dummy_check_takes_as_long_as_a_real_one(stored_hash: str) -> None:
    hasher = Argon2PasswordHasher()
    await hasher.verify(stored_hash, PASSWORD)

    started = time.perf_counter()
    for _ in range(3):
        await hasher.verify(stored_hash, "wrong passphrase")
    real = time.perf_counter() - started
    started = time.perf_counter()
    for _ in range(3):
        await hasher.verify_dummy("wrong passphrase")
    dummy = time.perf_counter() - started

    assert dummy > real / 2


async def test_checks_share_the_hashing_slots(monkeypatch: pytest.MonkeyPatch) -> None:
    slow = RecordingVerify(delay=0.05)
    hasher = Argon2PasswordHasher(max_concurrent=2)
    stored = argon2.PasswordHasher(time_cost=1, memory_cost=8192).hash(PASSWORD)
    monkeypatch.setattr(argon2.PasswordHasher, "verify", slow)

    await asyncio.gather(
        *(hasher.verify(stored, PASSWORD) for _ in range(4)),
        *(hasher.verify_dummy(PASSWORD) for _ in range(4)),
    )

    assert slow.peak == 2


def test_login_success_event_names_user_and_method() -> None:
    user_id = uuid.uuid7()

    with structlog.testing.capture_logs() as records:
        StructlogSecurityEvents().login_succeeded(user_id, LoginMethod.PASSWORD)

    assert records == [
        {
            "event": "security.login_succeeded",
            "user_id": str(user_id),
            "method": "password",
            "log_level": "info",
        }
    ]


@pytest.mark.parametrize("reason", ["bad_credentials", "email_not_verified"])
def test_login_failure_event_carries_only_the_reason(reason: str) -> None:
    with structlog.testing.capture_logs() as records:
        StructlogSecurityEvents().login_failed(reason)

    assert records == [{"event": "security.login_failed", "reason": reason, "log_level": "info"}]


def test_logout_event_names_the_user() -> None:
    user_id = uuid.uuid7()

    with structlog.testing.capture_logs() as records:
        StructlogSecurityEvents().logout(user_id)

    assert records == [{"event": "security.logout", "user_id": str(user_id), "log_level": "info"}]


def test_anonymous_logout_event_has_no_user() -> None:
    with structlog.testing.capture_logs() as records:
        StructlogSecurityEvents().logout(None)

    assert records == [{"event": "security.logout", "user_id": None, "log_level": "info"}]
