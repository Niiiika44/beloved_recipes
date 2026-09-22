from collections.abc import AsyncIterator, MutableMapping
from pathlib import Path
from typing import Any

import httpx
import pytest
import structlog
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, field_validator

from app.api.exceptions import CATEGORY_PROBLEMS, problem_type, spec_for
from app.api.schemas import BLANK_TYPE
from app.core.exceptions import (
    AppError,
    ConflictError,
    InvalidInputError,
    NotFoundError,
    PermissionDeniedError,
)
from app.main import create_app

CORE_EXCEPTIONS = Path(__file__).resolve().parents[1] / "app" / "core" / "exceptions.py"
PROBLEM_JSON = "application/problem+json"
SECRET_IN_MESSAGE = "postgresql://admin:hunter2@db.internal/recipes"


class RecipeNotFoundError(NotFoundError):
    code = "recipe_not_found"


class NotAWorkspaceMemberError(PermissionDeniedError):
    code = "not_a_workspace_member"


class OrderAlreadyClosedError(ConflictError):
    code = "order_already_closed"


class InviteExpiredError(InvalidInputError):
    code = "invite_expired"


class Amount(BaseModel):
    amount: int


class PositiveAmount(BaseModel):
    amount: int

    @field_validator("amount")
    @classmethod
    def positive(cls, value: int) -> int:
        if value <= 0:
            raise ValueError("must be positive")
        return value


class Pin(BaseModel):
    pin: int


def _build_app() -> FastAPI:
    app = create_app()

    @app.get("/t/not-found")
    async def not_found() -> None:
        raise RecipeNotFoundError("Recipe abc not found")

    @app.get("/t/forbidden")
    async def forbidden() -> None:
        raise NotAWorkspaceMemberError("Not a member")

    @app.get("/t/conflict")
    async def conflict() -> None:
        raise OrderAlreadyClosedError("Order is closed")

    @app.get("/t/invalid")
    async def invalid() -> None:
        raise InviteExpiredError("Invite expired")

    @app.get("/t/bare")
    async def bare() -> None:
        raise AppError("uncategorized")

    @app.post("/t/amount")
    async def amount(body: Amount) -> dict[str, int]:
        return {"amount": body.amount}

    @app.post("/t/positive")
    async def positive(body: PositiveAmount) -> dict[str, int]:
        return {"amount": body.amount}

    @app.post("/t/pin")
    async def pin(body: Pin) -> dict[str, int]:
        return {"pin": body.pin}

    @app.get("/t/auth")
    async def auth() -> None:
        raise HTTPException(401, detail="login required", headers={"WWW-Authenticate": "Bearer"})

    @app.get("/t/dict-detail")
    async def dict_detail() -> None:
        raise HTTPException(400, detail={"internal": "structure"})

    @app.get("/t/boom")
    async def boom() -> None:
        raise RuntimeError(SECRET_IN_MESSAGE)

    @app.get("/t/boom-empty")
    async def boom_empty() -> None:
        raise RuntimeError

    return app


@pytest.fixture
async def client() -> AsyncIterator[httpx.AsyncClient]:
    transport = httpx.ASGITransport(_build_app(), raise_app_exceptions=False)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as instance:
        yield instance


def _errors_logged(records: list[MutableMapping[str, Any]]) -> list[MutableMapping[str, Any]]:
    return [record for record in records if record["event"] == "app.request_error"]


@pytest.mark.parametrize(
    ("error", "status"),
    [
        (RecipeNotFoundError("x"), 404),
        (NotAWorkspaceMemberError("x"), 403),
        (OrderAlreadyClosedError("x"), 409),
        (InviteExpiredError("x"), 422),
        (AppError("x"), 500),
    ],
)
def test_spec_follows_inheritance(error: AppError, status: int) -> None:
    assert spec_for(error).status == status


def test_spec_does_not_depend_on_table_order(monkeypatch: pytest.MonkeyPatch) -> None:
    reversed_table = dict(reversed(list(CATEGORY_PROBLEMS.items())))
    monkeypatch.setattr("app.api.exceptions.CATEGORY_PROBLEMS", reversed_table)

    assert spec_for(RecipeNotFoundError("x")).status == 404


@pytest.mark.parametrize(
    ("code", "expected"),
    [
        ("recipe_not_found", "/problems/recipe-not-found"),
        ("validation_error", "/problems/validation-error"),
        ("app_error", "/problems/app-error"),
    ],
)
def test_problem_type_is_relative_path(code: str, expected: str) -> None:
    assert problem_type(code) == expected


def test_domain_layer_knows_nothing_about_http() -> None:
    source = CORE_EXCEPTIONS.read_text(encoding="utf-8")

    assert "fastapi" not in source
    assert "starlette" not in source


async def test_domain_error_becomes_problem_details(client: httpx.AsyncClient) -> None:
    response = await client.get("/t/not-found")
    body = response.json()

    assert response.status_code == 404
    assert response.headers["content-type"] == PROBLEM_JSON
    assert body["type"] == "/problems/recipe-not-found"
    assert body["status"] == 404
    assert body["detail"] == "Recipe abc not found"
    assert body["instance"] == "/t/not-found"
    assert body["title"]
    assert body["request_id"]


@pytest.mark.parametrize(
    ("path", "status", "problem"),
    [
        ("/t/forbidden", 403, "/problems/not-a-workspace-member"),
        ("/t/conflict", 409, "/problems/order-already-closed"),
        ("/t/invalid", 422, "/problems/invite-expired"),
    ],
)
async def test_categories_map_to_status(
    client: httpx.AsyncClient, path: str, status: int, problem: str
) -> None:
    response = await client.get(path)

    assert response.status_code == status
    assert response.json()["type"] == problem


async def test_uncategorized_error_is_500_and_logged(client: httpx.AsyncClient) -> None:
    with structlog.testing.capture_logs() as records:
        response = await client.get("/t/bare")

    assert response.status_code == 500
    logged = _errors_logged(records)
    assert len(logged) == 1
    assert isinstance(logged[0]["exc_info"], AppError)


async def test_unknown_path_has_blank_type(client: httpx.AsyncClient) -> None:
    response = await client.get("/nope")

    assert response.status_code == 404
    assert response.headers["content-type"] == PROBLEM_JSON
    assert response.json()["type"] == BLANK_TYPE


async def test_method_not_allowed_keeps_allow_header(client: httpx.AsyncClient) -> None:
    response = await client.get("/t/amount")

    assert response.status_code == 405
    assert response.headers["allow"] == "POST"
    assert response.headers["content-type"] == PROBLEM_JSON


async def test_http_exception_keeps_its_headers(client: httpx.AsyncClient) -> None:
    response = await client.get("/t/auth")

    assert response.status_code == 401
    assert response.headers["www-authenticate"] == "Bearer"
    assert response.json()["detail"] == "login required"


async def test_non_string_detail_is_dropped(client: httpx.AsyncClient) -> None:
    response = await client.get("/t/dict-detail")

    assert response.status_code == 400
    assert "detail" not in response.json()
    assert "internal" not in response.text


async def test_validation_error_lists_fields(client: httpx.AsyncClient) -> None:
    response = await client.post("/t/amount", json={"amount": "not-a-number"})
    body = response.json()

    assert response.status_code == 422
    assert response.headers["content-type"] == PROBLEM_JSON
    assert body["type"] == "/problems/validation-error"
    assert len(body["errors"]) == 1
    assert set(body["errors"][0]) == {"loc", "msg", "type"}
    assert body["errors"][0]["loc"] == ["body", "amount"]


async def test_validation_error_does_not_echo_input(client: httpx.AsyncClient) -> None:
    response = await client.post("/t/pin", json={"pin": "secret-1234"})

    assert response.status_code == 422
    assert "secret-1234" not in response.text


async def test_custom_validator_still_yields_422(client: httpx.AsyncClient) -> None:
    response = await client.post("/t/positive", json={"amount": -5})

    assert response.status_code == 422
    assert response.json()["errors"][0]["loc"] == ["body", "amount"]


async def test_unexpected_error_hides_internals(client: httpx.AsyncClient) -> None:
    response = await client.get("/t/boom")

    assert response.status_code == 500
    assert response.headers["content-type"] == PROBLEM_JSON
    assert response.json()["type"] == BLANK_TYPE
    assert "hunter2" not in response.text
    assert "Traceback" not in response.text
    assert "RuntimeError" not in response.text


async def test_unexpected_error_carries_request_id_header(client: httpx.AsyncClient) -> None:
    response = await client.get("/t/boom")

    assert response.headers["x-request-id"] == response.json()["request_id"]


@pytest.mark.parametrize("path", ["/t/boom", "/t/boom-empty"])
async def test_unexpected_error_is_logged_with_exception(
    client: httpx.AsyncClient, path: str
) -> None:
    with structlog.testing.capture_logs() as records:
        await client.get(path)

    logged = _errors_logged(records)
    assert len(logged) == 1
    assert isinstance(logged[0]["exc_info"], RuntimeError)


async def test_request_id_header_matches_body(client: httpx.AsyncClient) -> None:
    response = await client.get("/nope", headers={"X-Request-ID": "client-abc-123"})

    assert response.headers["x-request-id"] == "client-abc-123"
    assert response.json()["request_id"] == "client-abc-123"


@pytest.mark.parametrize(
    ("method", "path", "payload"),
    [
        ("GET", "/nope", None),
        ("GET", "/t/not-found", None),
        ("POST", "/t/amount", {"amount": "x"}),
    ],
)
async def test_client_errors_are_not_logged_as_errors(
    client: httpx.AsyncClient, method: str, path: str, payload: dict[str, str] | None
) -> None:
    with structlog.testing.capture_logs() as records:
        await client.request(method, path, json=payload)

    assert _errors_logged(records) == []


async def test_empty_fields_are_omitted(client: httpx.AsyncClient) -> None:
    body = (await client.get("/t/not-found")).json()

    assert "errors" not in body
    assert None not in body.values()
