from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager

import structlog
from fastapi import APIRouter, FastAPI

from app.api.exceptions import register_exception_handlers
from app.api.health import router as health_router
from app.core.config import get_settings
from app.core.db import dispose_engine, get_engine
from app.core.logging import configure_logging
from app.core.middleware import request_context
from app.core.redis import close_redis, get_redis

logger = structlog.get_logger(__name__)

API_V1_PREFIX = "/api/v1"


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None]:
    configure_logging()
    try:
        yield
    finally:
        try:
            if get_engine.cache_info().currsize > 0:
                await dispose_engine()
        except Exception as exc:
            logger.warning("app.dispose_engine_unavailable", error=str(exc))
        try:
            if get_redis.cache_info().currsize > 0:
                await close_redis()
        except Exception as exc:
            logger.warning("app.redis_close_unavailable", error=str(exc))


def create_app() -> FastAPI:
    settings = get_settings()
    app = FastAPI(
        title=settings.app.name,
        lifespan=lifespan,
        docs_url=None if settings.app.is_prod else "/docs",
        redoc_url=None if settings.app.is_prod else "/redoc",
        openapi_url=None if settings.app.is_prod else "/openapi.json",
    )
    register_exception_handlers(app)
    app.middleware("http")(request_context)
    api_router = APIRouter(prefix=API_V1_PREFIX)
    app.include_router(api_router)
    app.include_router(health_router)
    return app


app = create_app()
