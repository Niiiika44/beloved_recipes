from collections.abc import AsyncIterator, Iterator, MutableMapping
from typing import Any

import httpx
import pytest
import structlog
from fastapi import FastAPI

from app.core.context import NO_REQUEST_ID, get_request_id
from app.core.middleware import is_valid_request_id, request_context

RECIPE_ROUTE = "/api/v1/recipes/{recipe_id}"


@pytest.fixture
def app() -> FastAPI:
    application = FastAPI()
    application.middleware("http")(request_context)

    @application.get(RECIPE_ROUTE)
    async def get_recipe(recipe_id: str) -> dict[str, str]:
        structlog.get_logger("test").info("внутри эндпоинта", seen_id=get_request_id())
        return {"id": recipe_id}

    @application.post("/api/v1/recipes")
    async def create_recipe() -> dict[str, bool]:
        return {"created": True}

    @application.get("/boom")
    async def boom() -> None:
        raise RuntimeError("взрыв")

    return application


@pytest.fixture
async def client(app: FastAPI) -> AsyncIterator[httpx.AsyncClient]:
    transport = httpx.ASGITransport(app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as instance:
        yield instance


@pytest.fixture
def captured() -> Iterator[list[MutableMapping[str, Any]]]:
    with structlog.testing.capture_logs() as records:
        yield records


def _access(records: list[MutableMapping[str, Any]]) -> MutableMapping[str, Any]:
    entries = [record for record in records if record["event"] == "http.requested"]
    assert len(entries) == 1
    return entries[0]


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("abc-123", True),
        ("ABC_123", True),
        ("0193f2ab7c114d8e9f2a1b3c4d5e6f70", True),
        ("a" * 64, True),
        ("a" * 65, False),
        ("", False),
        ("with space", False),
        ("with\nnewline", False),
        ("with\rreturn", False),
        ("semi;colon", False),
        ("кириллица", False),
    ],
)
def test_request_id_validation(value: str, expected: bool) -> None:
    assert is_valid_request_id(value) is expected


async def test_request_id_is_generated_when_absent(client: httpx.AsyncClient) -> None:
    response = await client.get("/api/v1/recipes/abc")

    request_id = response.headers["x-request-id"]
    assert is_valid_request_id(request_id)
    assert len(request_id) == 32


async def test_generated_ids_differ_between_requests(client: httpx.AsyncClient) -> None:
    first = await client.get("/api/v1/recipes/abc")
    second = await client.get("/api/v1/recipes/abc")

    assert first.headers["x-request-id"] != second.headers["x-request-id"]


async def test_valid_incoming_id_is_reused(client: httpx.AsyncClient) -> None:
    response = await client.get("/api/v1/recipes/abc", headers={"X-Request-ID": "client-abc-123"})

    assert response.headers["x-request-id"] == "client-abc-123"


@pytest.mark.parametrize("forged", ["a" * 65, "with space", "semi;colon", ""])
async def test_forged_incoming_id_is_replaced(client: httpx.AsyncClient, forged: str) -> None:
    response = await client.get("/api/v1/recipes/abc", headers={"X-Request-ID": forged})

    request_id = response.headers["x-request-id"]
    assert request_id != forged
    assert len(request_id) == 32


async def test_endpoint_sees_the_same_request_id(
    client: httpx.AsyncClient, captured: list[MutableMapping[str, Any]]
) -> None:
    response = await client.get("/api/v1/recipes/abc", headers={"X-Request-ID": "client-abc-123"})

    inside = [record for record in captured if record["event"] == "внутри эндпоинта"]
    assert len(inside) == 1
    assert inside[0]["seen_id"] == "client-abc-123"
    assert inside[0]["seen_id"] == response.headers["x-request-id"]


async def test_context_does_not_leak_between_requests(
    client: httpx.AsyncClient, captured: list[MutableMapping[str, Any]]
) -> None:
    await client.get("/api/v1/recipes/abc", headers={"X-Request-ID": "first-id"})
    await client.get("/api/v1/recipes/abc")

    seen = [record["seen_id"] for record in captured if record["event"] == "внутри эндпоинта"]
    assert len(seen) == 2
    assert seen[0] == "first-id"
    assert seen[1] != "first-id"
    assert seen[1] != NO_REQUEST_ID


async def test_access_log_uses_route_template(
    client: httpx.AsyncClient, captured: list[MutableMapping[str, Any]]
) -> None:
    await client.get("/api/v1/recipes/0193f2ab-7c11")

    entry = _access(captured)
    assert entry["route"] == RECIPE_ROUTE
    assert "0193f2ab-7c11" not in str(entry)


async def test_access_log_records_method_and_status(
    client: httpx.AsyncClient, captured: list[MutableMapping[str, Any]]
) -> None:
    await client.post("/api/v1/recipes")

    entry = _access(captured)
    assert entry["method"] == "POST"
    assert entry["status"] == 200


async def test_access_log_records_duration(
    client: httpx.AsyncClient, captured: list[MutableMapping[str, Any]]
) -> None:
    await client.get("/api/v1/recipes/abc")

    assert _access(captured)["duration_ms"] > 0


async def test_unmatched_path_is_not_logged_verbatim(
    client: httpx.AsyncClient, captured: list[MutableMapping[str, Any]]
) -> None:
    await client.get("/wp-admin/setup-config.php")

    entry = _access(captured)
    assert entry["route"] == "<unmatched>"
    assert entry["status"] == 404
    assert "wp-admin" not in str(entry)


async def test_unmatched_path_still_returns_request_id(client: httpx.AsyncClient) -> None:
    response = await client.get("/nope")

    assert response.status_code == 404
    assert is_valid_request_id(response.headers["x-request-id"])


async def test_failing_endpoint_is_logged_and_reraised(
    client: httpx.AsyncClient, captured: list[MutableMapping[str, Any]]
) -> None:
    with pytest.raises(RuntimeError, match="взрыв"):
        await client.get("/boom")

    entry = _access(captured)
    assert entry["status"] == 500
    assert entry["route"] == "/boom"
    assert entry["duration_ms"] > 0


def test_request_id_outside_request_is_placeholder() -> None:
    structlog.contextvars.clear_contextvars()

    assert get_request_id() == NO_REQUEST_ID
