import json
import uuid
from datetime import timedelta
from typing import Any

import httpx
import pytest
from fastapi import FastAPI
from redis.asyncio import Redis
from sqlalchemy import func, select, update

from app.core.db import get_engine, get_session_factory
from app.core.redis import get_redis
from app.modules.identity.domain.enums import TokenPurpose
from app.modules.identity.infrastructure.models import EmailJob, User
from app.modules.identity.infrastructure.redis_one_time_token_store import RedisOneTimeTokenStore
from app.modules.identity.infrastructure.redis_rate_limiter import RedisRateLimiter
from app.modules.identity.infrastructure.repositories import SqlUserRepository
from app.modules.identity.routes.dependencies import get_one_time_token_store, get_rate_limiter

CONFIRM = "/api/v1/auth/email/confirm"
RESEND = "/api/v1/auth/email/resend"
PROBLEM_JSON = "application/problem+json"


async def _user(email: str = "anna@example.org", verified: bool = False) -> uuid.UUID:
    async with get_session_factory()() as session:
        user_id = await SqlUserRepository(session).create(email, "Anna")
        assert user_id is not None
        if verified:
            await session.execute(
                update(User).where(User.id == user_id).values(email_verified_at=func.now())
            )
        await session.commit()
    return user_id


async def _token(user_id: uuid.UUID, purpose: TokenPurpose = TokenPurpose.EMAIL_CONFIRM) -> str:
    store = RedisOneTimeTokenStore(client=get_redis(), operation_timeout_seconds=1.0)
    return await store.issue(purpose, user_id, 0, timedelta(hours=24))


async def _verified(user_id: uuid.UUID) -> bool:
    async with get_engine().connect() as connection:
        moment = await connection.scalar(select(User.email_verified_at).where(User.id == user_id))
    return moment is not None


async def _jobs() -> int:
    async with get_engine().connect() as connection:
        count = await connection.scalar(select(func.count()).select_from(EmailJob))
    return int(count or 0)


async def test_confirmation_link_verifies_the_email(client: httpx.AsyncClient) -> None:
    user_id = await _user()
    token = await _token(user_id)

    response = await client.post(CONFIRM, json={"token": token})

    assert response.status_code == 204
    assert response.content == b""
    assert response.headers["cache-control"] == "no-store"
    assert await _verified(user_id)


async def test_used_link_is_422(client: httpx.AsyncClient) -> None:
    token = await _token(await _user())
    await client.post(CONFIRM, json={"token": token})

    response = await client.post(CONFIRM, json={"token": token})

    assert response.status_code == 422
    assert response.headers["content-type"] == PROBLEM_JSON
    assert response.json()["type"] == "/problems/token-invalid"


@pytest.mark.parametrize("token", ["short", "A" * 43], ids=["malformed", "unknown"])
async def test_bad_link_is_422_like_a_used_one(client: httpx.AsyncClient, token: str) -> None:
    response = await client.post(CONFIRM, json={"token": token})

    assert response.status_code == 422
    assert response.json()["type"] == "/problems/token-invalid"


async def test_reset_link_does_not_confirm_the_email(client: httpx.AsyncClient) -> None:
    user_id = await _user()
    token = await _token(user_id, TokenPurpose.PASSWORD_RESET)

    response = await client.post(CONFIRM, json={"token": token})

    assert response.status_code == 422
    assert not await _verified(user_id)


@pytest.mark.parametrize(
    ("path", "content", "content_type"),
    [
        (CONFIRM, json.dumps({"token": "A" * 43}), "text/plain"),
        (CONFIRM, json.dumps({"token": "A" * 43, "extra": 1}), "application/json"),
        (RESEND, json.dumps({"email": "anna@example.org"}), "text/plain"),
        (RESEND, json.dumps({"email": "not-an-email"}), "application/json"),
        (RESEND, json.dumps({"email": "anna@example.org", "extra": 1}), "application/json"),
    ],
    ids=["confirm_text", "confirm_extra", "resend_text", "resend_bad_email", "resend_extra"],
)
async def test_malformed_request_is_validation_error(
    client: httpx.AsyncClient, path: str, content: str, content_type: str
) -> None:
    response = await client.post(path, content=content, headers={"Content-Type": content_type})

    assert response.status_code == 422
    assert response.json()["type"] == "/problems/validation-error"


async def test_token_store_outage_is_503(
    app: FastAPI, client: httpx.AsyncClient, dead_redis: Redis
) -> None:
    app.dependency_overrides[get_one_time_token_store] = lambda: RedisOneTimeTokenStore(
        client=dead_redis, operation_timeout_seconds=0.5
    )

    response = await client.post(CONFIRM, json={"token": "A" * 43})

    assert response.status_code == 503


async def test_resend_queues_a_letter_for_unverified_email(client: httpx.AsyncClient) -> None:
    await _user()

    response = await client.post(RESEND, json={"email": "ANNA@example.org"})

    assert response.status_code == 202
    assert response.content == b""
    assert response.headers["cache-control"] == "no-store"
    assert await _jobs() == 1


@pytest.mark.parametrize("verified", [True, None], ids=["verified", "unknown"])
async def test_resend_answers_the_same_and_queues_nothing(
    client: httpx.AsyncClient, verified: bool | None
) -> None:
    if verified is not None:
        await _user(verified=verified)

    response = await client.post(RESEND, json={"email": "anna@example.org"})

    assert response.status_code == 202
    assert response.content == b""
    assert await _jobs() == 0


async def test_sixth_resend_in_an_hour_is_429(client: httpx.AsyncClient) -> None:
    statuses = [
        (await client.post(RESEND, json={"email": email})).status_code
        for email in ["anna@example.org", "ANNA@example.org"] * 3
    ]
    refused = await client.post(RESEND, json={"email": "anna@example.org"})

    assert statuses == [202] * 5 + [429]
    assert refused.json()["type"] == "/problems/rate-limited"
    assert 1 <= int(refused.headers["retry-after"]) <= 3600


async def test_resend_limit_does_not_touch_registration(client: httpx.AsyncClient) -> None:
    for _ in range(6):
        await client.post(RESEND, json={"email": "anna@example.org"})

    keys = sorted(await get_redis().keys("rate_limit:*"))

    assert all(str(key).startswith("rate_limit:resend_confirmation_") for key in keys)


async def test_resend_limiter_outage_is_503(
    app: FastAPI, client: httpx.AsyncClient, dead_redis: Redis
) -> None:
    app.dependency_overrides[get_rate_limiter] = lambda: RedisRateLimiter(
        client=dead_redis, operation_timeout_seconds=0.5
    )

    response = await client.post(RESEND, json={"email": "anna@example.org"})

    assert response.status_code == 503


def test_openapi_documents_confirmation_endpoints(app: FastAPI) -> None:
    paths = app.openapi()["paths"]
    confirm: dict[str, Any] = paths[CONFIRM]["post"]
    resend: dict[str, Any] = paths[RESEND]["post"]

    assert {"204", "422", "503"} <= set(confirm["responses"])
    assert {"202", "422", "429", "503"} <= set(resend["responses"])


async def test_redis_holds_no_plain_token(client: httpx.AsyncClient) -> None:
    token = await _token(await _user())

    keys = await get_redis().keys("auth_token:*")

    assert keys
    assert all(token not in str(key) for key in keys)
