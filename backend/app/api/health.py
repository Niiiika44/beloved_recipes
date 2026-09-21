import asyncio

import structlog
from fastapi import APIRouter, Response, status
from sqlalchemy import text

from app.core.db import get_engine
from app.core.redis import get_redis

CHECK_TIMEOUT_SECONDS = 2.0

logger = structlog.get_logger(__name__)

router = APIRouter(
    tags=["infra"],
)


async def _check_postgres() -> bool:
    try:
        async with asyncio.timeout(CHECK_TIMEOUT_SECONDS):
            async with get_engine().connect() as connection:
                await connection.execute(text("SELECT 1"))
    except Exception as exc:
        logger.warning("readyz.postgres_unavailable", error=str(exc))
        return False
    return True


async def _check_redis() -> bool:
    try:
        async with asyncio.timeout(CHECK_TIMEOUT_SECONDS):
            return await get_redis().ping()
    except Exception as exc:
        logger.warning("readyz.redis_unavailable", error=str(exc))
        return False


@router.get(
    "/healthz",
    summary="Liveness probe",
)
async def health_check() -> dict[str, str]:
    return {"status": "ok"}


@router.get(
    "/readyz",
    summary="Readiness probe of redis and postgres",
    responses={503: {"description": "Redis/Postgres/both are unavailable"}},
)
async def readiness_check(response: Response) -> dict[str, str | dict[str, str]]:
    postgres_ok, redis_ok = await asyncio.gather(
        _check_postgres(),
        _check_redis(),
    )
    overall_ok = postgres_ok and redis_ok
    response.status_code = status.HTTP_200_OK if overall_ok else status.HTTP_503_SERVICE_UNAVAILABLE
    return {
        "status": "ok" if overall_ok else "fail",
        "checks": {
            "postgres": "ok" if postgres_ok else "fail",
            "redis": "ok" if redis_ok else "fail",
        },
    }
