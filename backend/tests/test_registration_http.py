import asyncio
import hashlib
import json
import logging
import threading
import time
from collections import Counter
from typing import Annotated, Any

import argon2
import httpx
import pytest
import structlog
from fakes import FakeBreachChecker, FakeHasher
from fastapi import Depends, FastAPI
from redis.asyncio import Redis
from sqlalchemy import func, select, text

from app.core.config import get_settings
from app.core.db import get_engine
from app.core.models import Base
from app.core.redis import get_redis
from app.modules.identity.domain.emails import email_fingerprint
from app.modules.identity.infrastructure.models import EmailJob, PasswordCredential, User
from app.modules.identity.infrastructure.pwned_passwords_checker import PwnedPasswordsChecker
from app.modules.identity.infrastructure.redis_rate_limiter import RedisRateLimiter
from app.modules.identity.infrastructure.structlog_security_events import (
    StructlogSecurityEvents,
)
from app.modules.identity.routes.dependencies import (
    get_breach_checker,
    get_limit_secret,
    get_password_hasher,
    get_rate_limiter,
    get_registration_service,
    get_security_events,
    get_uow,
)
from app.modules.identity.service.ports import (
    BreachedPasswordChecker,
    PasswordHasher,
    RateLimiter,
    SecurityEvents,
    UnitOfWork,
)
from app.modules.identity.service.registration import RegistrationService

REGISTER = "/api/v1/auth/register"
PROBLEM_JSON = "application/problem+json"
PASSWORD = "correct horse battery"
BODY = {"email": "Anna@Example.org", "password": PASSWORD, "display_name": "  Anna  "}


@pytest.fixture
def breach(app: FastAPI) -> FakeBreachChecker:
    checker = FakeBreachChecker(False)
    app.dependency_overrides[get_breach_checker] = lambda: checker
    return checker


@pytest.fixture
def fast_hashing(app: FastAPI) -> None:
    hasher = FakeHasher()
    app.dependency_overrides[get_password_hasher] = lambda: hasher


async def _register(client: httpx.AsyncClient, **overrides: Any) -> httpx.Response:
    return await client.post(REGISTER, json=BODY | overrides)


async def _rows(sql: str) -> list[Any]:
    async with get_engine().connect() as connection:
        return list((await connection.execute(text(sql))).all())


async def _count(model: type[Base]) -> int:
    async with get_engine().connect() as connection:
        count = await connection.scalar(select(func.count()).select_from(model))
    return int(count or 0)


async def _jobs() -> list[str]:
    return sorted(row[0] for row in await _rows("SELECT purpose::text FROM email_jobs"))


async def _stored_hash() -> str:
    [(password_hash,)] = await _rows("SELECT password_hash FROM password_credentials")
    return str(password_hash)


def _client_from(app: FastAPI, ip: str) -> httpx.AsyncClient:
    transport = httpx.ASGITransport(app, raise_app_exceptions=False, client=(ip, 5000))
    return httpx.AsyncClient(transport=transport, base_url="http://test")


async def test_new_email_registers_user(
    client: httpx.AsyncClient, breach: FakeBreachChecker
) -> None:
    response = await _register(client)

    assert response.status_code == 202
    assert response.content == b""
    assert response.headers["cache-control"] == "no-store"
    assert await _rows(
        "SELECT email, display_name, nickname, email_verified_at, avatar_url FROM users"
    ) == [("Anna@example.org", "Anna", None, None, None)]
    stored = await _stored_hash()
    assert stored.startswith("$argon2id$")
    assert argon2.PasswordHasher().verify(stored, PASSWORD)
    assert await _rows("SELECT purpose::text, status::text, attempts FROM email_jobs") == [
        ("email_confirm", "pending", 0)
    ]


@pytest.mark.parametrize("again", ["anna@example.org", "ANNA@EXAMPLE.ORG"])
async def test_taken_email_answers_the_same_and_keeps_the_password(
    client: httpx.AsyncClient, breach: FakeBreachChecker, again: str
) -> None:
    await _register(client)
    first_hash = await _stored_hash()

    response = await _register(client, email=again, password="another long passphrase")

    assert response.status_code == 202
    assert response.content == b""
    assert await _count(User) == 1
    assert await _stored_hash() == first_hash
    assert await _jobs() == ["already_registered", "email_confirm"]


async def test_verified_account_gets_already_registered(
    client: httpx.AsyncClient, breach: FakeBreachChecker
) -> None:
    await _register(client)
    async with get_engine().begin() as connection:
        await connection.execute(text("UPDATE users SET email_verified_at = now()"))
        await connection.execute(text("DELETE FROM email_jobs"))

    await _register(client)

    assert await _jobs() == ["already_registered"]


async def test_repeated_registration_on_taken_email_queues_one_letter(
    client: httpx.AsyncClient, breach: FakeBreachChecker
) -> None:
    for _ in range(4):
        await _register(client)

    assert await _jobs() == ["already_registered", "email_confirm"]


async def test_parallel_registrations_of_one_email_create_one_user(
    client: httpx.AsyncClient, breach: FakeBreachChecker
) -> None:
    responses = await asyncio.gather(
        *(
            _register(client, email=email)
            for email in ("anna@example.org", "ANNA@example.org", "Anna@EXAMPLE.org")
        )
    )

    assert [response.status_code for response in responses] == [202, 202, 202]
    assert await _count(User) == 1
    assert await _count(PasswordCredential) == 1
    assert await _jobs() == ["already_registered", "email_confirm"]


@pytest.mark.parametrize(
    ("password", "reason"),
    [("short", "too_short"), ("        ", "blank"), ("x" * 129, "too_long")],
)
async def test_weak_password_is_422_with_reason(
    client: httpx.AsyncClient, breach: FakeBreachChecker, password: str, reason: str
) -> None:
    response = await _register(client, password=password)

    assert response.status_code == 422
    assert response.headers["content-type"] == PROBLEM_JSON
    assert response.json()["type"] == "/problems/password-weak"
    assert response.json()["errors"][0]["loc"] == ["body", "password"]
    assert response.json()["errors"][0]["type"] == reason
    assert await _count(User) == 0


async def test_invalid_display_name_is_422(
    client: httpx.AsyncClient, breach: FakeBreachChecker
) -> None:
    response = await _register(client, display_name="   ")

    assert response.status_code == 422
    assert response.json()["type"] == "/problems/display-name-invalid"
    assert await _count(User) == 0


async def test_breached_password_is_422_and_nothing_is_saved(
    client: httpx.AsyncClient, breach: FakeBreachChecker
) -> None:
    breach.answer = True

    response = await _register(client)

    assert response.status_code == 422
    assert response.json()["errors"][0]["type"] == "breached"
    assert await _count(User) == 0
    assert await _count(EmailJob) == 0


async def test_unavailable_breach_check_lets_registration_through(
    client: httpx.AsyncClient, breach: FakeBreachChecker
) -> None:
    breach.answer = None

    with structlog.testing.capture_logs() as records:
        response = await _register(client)

    assert response.status_code == 202
    assert await _count(User) == 1
    assert {"event": "security.breach_check_unavailable", "log_level": "warning"} in records


@pytest.mark.parametrize(
    ("content", "content_type"),
    [
        (json.dumps(BODY), "text/plain"),
        (json.dumps(BODY | {"role": "admin"}), "application/json"),
        (json.dumps(BODY | {"email": "not-an-email"}), "application/json"),
        (json.dumps({"email": "anna@example.org", "password": PASSWORD}), "application/json"),
    ],
    ids=["text_plain", "unknown_field", "bad_email", "missing_field"],
)
async def test_malformed_request_is_422_validation_error(
    client: httpx.AsyncClient, breach: FakeBreachChecker, content: str, content_type: str
) -> None:
    response = await client.post(REGISTER, content=content, headers={"Content-Type": content_type})

    assert response.status_code == 422
    assert response.json()["type"] == "/problems/validation-error"
    assert await _count(User) == 0


async def test_format_errors_do_not_spend_the_limits(
    client: httpx.AsyncClient, breach: FakeBreachChecker, fast_hashing: None
) -> None:
    rejected = [(await _register(client, password="short")).status_code for _ in range(10)]
    accepted = [(await _register(client)).status_code for _ in range(5)]

    assert set(rejected) == {422}
    assert accepted == [202] * 5


async def test_sixth_registration_on_one_email_is_429_in_any_case(
    client: httpx.AsyncClient, breach: FakeBreachChecker, fast_hashing: None
) -> None:
    emails = ["anna@example.org", "ANNA@example.org", "Anna@Example.org"] * 2

    with structlog.testing.capture_logs() as records:
        statuses = [(await _register(client, email=email)).status_code for email in emails]
        refused = await _register(client)

    assert statuses == [202] * 5 + [429]
    assert refused.status_code == 429
    assert refused.json()["type"] == "/problems/rate-limited"
    assert 1 <= int(refused.headers["retry-after"]) <= 3600
    assert {
        "event": "security.rate_limited",
        "action": "registration",
        "scope": "email",
        "log_level": "warning",
    } in records


async def test_twenty_first_registration_from_one_ip_is_429(
    app: FastAPI, breach: FakeBreachChecker, fast_hashing: None
) -> None:
    async with _client_from(app, "203.0.113.7") as busy, _client_from(app, "198.51.100.1") as other:
        statuses = [
            (await _register(busy, email=f"cook{index}@example.org")).status_code
            for index in range(21)
        ]
        elsewhere = await _register(other, email="fresh@example.org")

    assert statuses == [202] * 20 + [429]
    assert elsewhere.status_code == 202


async def test_limit_keys_hide_the_email(
    client: httpx.AsyncClient, breach: FakeBreachChecker
) -> None:
    await _register(client)

    keys = sorted(await get_redis().keys("rate_limit:*"))
    secret = get_settings().security.secret_key.get_secret_value().encode()
    assert keys == [
        "rate_limit:registration_email:" + email_fingerprint("anna@example.org", secret),
        "rate_limit:registration_ip:127.0.0.1",
    ]
    plain_sha = hashlib.sha256(b"anna@example.org").hexdigest()
    assert all("anna" not in key.lower() and plain_sha not in key for key in keys)


async def test_limiter_outage_is_503_and_nothing_is_saved(
    app: FastAPI, client: httpx.AsyncClient, breach: FakeBreachChecker, dead_redis: Redis
) -> None:
    app.dependency_overrides[get_rate_limiter] = lambda: RedisRateLimiter(
        client=dead_redis, operation_timeout_seconds=0.5
    )

    response = await _register(client)

    assert response.status_code == 503
    assert response.headers["content-type"] == PROBLEM_JSON
    assert await _count(User) == 0


async def test_many_registrations_on_one_pool_keep_queueing_letters(
    client: httpx.AsyncClient, breach: FakeBreachChecker, fast_hashing: None
) -> None:
    statuses = []
    for index in range(15):
        await get_redis().flushdb()
        response = await _register(client, email=f"cook{index % 3}@example.org")
        statuses.append(response.status_code)

    assert statuses == [202] * 15
    assert Counter(await _jobs()) == Counter({"already_registered": 3, "email_confirm": 3})


async def test_concurrent_registrations_share_four_hashing_slots(
    client: httpx.AsyncClient, breach: FakeBreachChecker, monkeypatch: pytest.MonkeyPatch
) -> None:
    active = 0
    peak = 0
    lock = threading.Lock()

    def slow_hash(hasher: argon2.PasswordHasher, password: str | bytes) -> str:
        nonlocal active, peak
        with lock:
            active += 1
            peak = max(peak, active)
        time.sleep(0.05)
        with lock:
            active -= 1
        return "$argon2id$slow"

    monkeypatch.setattr(argon2.PasswordHasher, "hash", slow_hash)

    responses = await asyncio.gather(
        *(_register(client, email=f"cook{index}@example.org") for index in range(10))
    )

    assert [response.status_code for response in responses] == [202] * 10
    assert peak == 4


@pytest.fixture
def services(app: FastAPI) -> tuple[list[RegistrationService], list[PasswordHasher]]:
    built: list[RegistrationService] = []
    hashers: list[PasswordHasher] = []

    def recording(
        uow: Annotated[UnitOfWork, Depends(get_uow)],
        limiter: Annotated[RateLimiter, Depends(get_rate_limiter)],
        hasher: Annotated[PasswordHasher, Depends(get_password_hasher)],
        breach_checker: Annotated[BreachedPasswordChecker, Depends(get_breach_checker)],
        events: Annotated[SecurityEvents, Depends(get_security_events)],
        secret: Annotated[bytes, Depends(get_limit_secret)],
    ) -> RegistrationService:
        service = get_registration_service(uow, limiter, hasher, breach_checker, events, secret)
        built.append(service)
        hashers.append(hasher)
        return service

    app.dependency_overrides[get_registration_service] = recording
    return built, hashers


async def test_each_request_gets_its_own_service_and_the_shared_hasher(
    client: httpx.AsyncClient,
    breach: FakeBreachChecker,
    services: tuple[list[RegistrationService], list[PasswordHasher]],
) -> None:
    await _register(client)
    await _register(client, email="boris@example.org")

    built, hashers = services
    assert len(built) == 2
    assert built[0] is not built[1]
    assert hashers[0] is hashers[1]


def test_limit_secret_comes_from_security_settings() -> None:
    settings = get_settings()

    assert get_limit_secret(settings) == settings.security.secret_key.get_secret_value().encode()


def test_production_dependencies_build_the_real_adapters() -> None:
    assert isinstance(get_breach_checker(), PwnedPasswordsChecker)
    assert isinstance(get_security_events(), StructlogSecurityEvents)


def test_password_hasher_is_one_per_process() -> None:
    get_password_hasher.cache_clear()

    assert get_password_hasher() is get_password_hasher()

    get_password_hasher.cache_clear()


async def test_password_never_reaches_the_logs(
    client: httpx.AsyncClient, breach: FakeBreachChecker, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.DEBUG)

    with structlog.testing.capture_logs() as records:
        await _register(client)
        await _register(client)
        await _register(client, password="x" * 129)
        breach.answer = None
        await _register(client, email="boris@example.org")

    everything = repr(records) + caplog.text
    assert PASSWORD not in everything
    assert "x" * 129 not in everything


def test_openapi_documents_registration(app: FastAPI) -> None:
    operation = app.openapi()["paths"][REGISTER]["post"]

    assert {"202", "422", "429", "503"} <= set(operation["responses"])
    schema_ref = operation["requestBody"]["content"]["application/json"]["schema"]["$ref"]
    schema = app.openapi()["components"]["schemas"][schema_ref.rsplit("/", 1)[1]]
    assert schema["required"] == ["email", "password", "display_name"]
    assert schema["additionalProperties"] is False
    assert schema["properties"]["email"]["format"] == "email"


async def test_registration_needs_no_session(
    client: httpx.AsyncClient, breach: FakeBreachChecker
) -> None:
    response = await _register(client)

    assert response.status_code == 202
    assert "set-cookie" not in response.headers
