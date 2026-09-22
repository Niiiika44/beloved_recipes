import http
from collections.abc import Mapping
from typing import Any, NamedTuple

import structlog
from fastapi import FastAPI, Request, Response, status
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.api.schemas import BLANK_TYPE, PROBLEM_TYPE_PATH, ProblemDetail
from app.core.context import get_request_id
from app.core.exceptions import (
    AppError,
    ConflictError,
    InvalidInputError,
    NotFoundError,
    PermissionDeniedError,
)

logger = structlog.get_logger(__name__)


class ProblemSpec(NamedTuple):
    status: int
    title: str


CATEGORY_PROBLEMS: dict[type[AppError], ProblemSpec] = {
    NotFoundError: ProblemSpec(404, "Resource is not found"),
    PermissionDeniedError: ProblemSpec(403, "Permission denied"),
    ConflictError: ProblemSpec(409, "Conflict"),
    InvalidInputError: ProblemSpec(422, "Invalid input data"),
    AppError: ProblemSpec(500, "Internal error"),
}


def _log_error(
    request: Request, status_code: int, error_type: str, message: str, exc_info: BaseException
) -> None:
    logger.error(
        "app.request_error",
        error_type=error_type,
        status_code=status_code,
        detail=message,
        path=request.url.path,
        method=request.method,
        exc_info=exc_info,
    )


def spec_for(error: AppError) -> ProblemSpec:
    for cls in type(error).__mro__:
        spec = CATEGORY_PROBLEMS.get(cls)
        if spec is not None:
            return spec
    return CATEGORY_PROBLEMS[AppError]


def problem_type(code: str) -> str:
    return PROBLEM_TYPE_PATH + code.replace("_", "-")


def problem_response(
    request: Request,
    *,
    status: int,
    title: str,
    detail: str | None = None,
    problem_type_uri: str = BLANK_TYPE,
    errors: list[dict[str, Any]] | None = None,
    headers: Mapping[str, str] | None = None,
) -> JSONResponse:
    request_id = get_request_id()
    all_headers = {**(headers or {}), "X-Request-ID": request_id}
    problem = ProblemDetail(
        type=problem_type_uri,
        title=title,
        status=status,
        detail=detail,
        instance=request.url.path,
        request_id=request_id,
        errors=errors,
    )
    return JSONResponse(
        problem.model_dump(mode="json", exclude_none=True),
        status_code=status,
        headers=all_headers,
        media_type="application/problem+json",
    )


async def handle_app_error(request: Request, exc: Exception) -> Response:
    if not isinstance(exc, AppError):
        raise ValueError("AppError expected")
    spec = spec_for(exc)
    if spec.status == 500:
        _log_error(
            request,
            status_code=500,
            error_type=type(exc).__name__,
            message=exc.message,
            exc_info=exc,
        )
    return problem_response(
        request,
        status=spec.status,
        title=spec.title,
        detail=exc.message,
        problem_type_uri=problem_type(exc.code),
    )


async def handle_http_exception(request: Request, exc: Exception) -> Response:
    if not isinstance(exc, StarletteHTTPException):
        raise ValueError("StarletteHTTPException expected")
    message = exc.detail if isinstance(exc.detail, str) else None
    return problem_response(
        request,
        status=exc.status_code,
        title=http.HTTPStatus(exc.status_code).phrase,
        detail=message,
        headers=exc.headers,
    )


async def handle_validation_error(request: Request, exc: Exception) -> Response:
    if not isinstance(exc, RequestValidationError):
        raise ValueError("RequestValidationError expected")
    errors = [{"loc": err["loc"], "msg": err["msg"], "type": err["type"]} for err in exc.errors()]
    message = (
        "; ".join(f"{'.'.join(str(loc) for loc in err['loc'])}: {err['msg']}" for err in errors)
        or "Validation error"
    )
    status_code = status.HTTP_422_UNPROCESSABLE_CONTENT
    return problem_response(
        request,
        status=status_code,
        title="Unprocessable content",
        detail=message,
        problem_type_uri=problem_type("validation_error"),
        errors=jsonable_encoder(errors),
    )


async def handle_unexpected_error(request: Request, exc: Exception) -> Response:
    status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
    _log_error(
        request,
        status_code=status_code,
        error_type=type(exc).__name__,
        message="unhandled_error",
        exc_info=exc,
    )
    return problem_response(
        request,
        status=status_code,
        title="Internal service error",
        detail="internal service error",
    )


def register_exception_handlers(app: FastAPI) -> None:
    app.add_exception_handler(AppError, handle_app_error)
    app.add_exception_handler(RequestValidationError, handle_validation_error)
    app.add_exception_handler(StarletteHTTPException, handle_http_exception)
    app.add_exception_handler(Exception, handle_unexpected_error)
