import re
import time
import uuid

import structlog
from fastapi import Request
from starlette.middleware.base import RequestResponseEndpoint
from starlette.responses import Response

logger = structlog.get_logger(__name__)


def is_valid_request_id(request_id: str) -> bool:
    if len(request_id) > 64:
        return False
    pattern = r"^[a-zA-Z0-9_-]+$"
    return bool(re.fullmatch(pattern, request_id))


async def request_context(request: Request, call_next: RequestResponseEndpoint) -> Response:
    request_id = request.headers.get("x-request-id")
    if request_id is None or not is_valid_request_id(request_id):
        request_id = uuid.uuid4().hex
    structlog.contextvars.clear_contextvars()
    structlog.contextvars.bind_contextvars(request_id=request_id)
    start = time.perf_counter()
    status = 500
    try:
        response = await call_next(request)
        response.headers["X-Request-ID"] = request_id
        status = response.status_code
        return response
    finally:
        duration_ms = (time.perf_counter() - start) * 1000
        route = getattr(request.scope.get("route"), "path", None) or "<unmatched>"
        user_id = getattr(request.state, "user_id", None)
        logger.info(
            "http.requested",
            method=request.method,
            route=route,
            status=status,
            duration_ms=duration_ms,
            user_id=str(user_id) if user_id is not None else None,
        )
