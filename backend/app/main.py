from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager

import httpx
import structlog
from fastapi import APIRouter, FastAPI

from app.api.exceptions import register_exception_handlers
from app.api.health import router as health_router
from app.api.paths import API_V1_PREFIX, GOOGLE_CALLBACK_PATH
from app.core.config import get_settings
from app.core.db import dispose_engine, get_session_factory
from app.core.logging import configure_logging
from app.core.middleware import request_context
from app.core.redis import close_redis, get_redis
from app.modules.identity.infrastructure.argon2_password_hasher import Argon2PasswordHasher
from app.modules.identity.infrastructure.google_oidc_provider import (
    GOOGLE_TIMEOUT_SECONDS,
    GoogleOidcProvider,
    JwksCache,
)
from app.modules.identity.routes.router import router as identity_router

logger = structlog.get_logger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None]:
    configure_logging()
    get_session_factory()
    get_redis()
    app.state.password_hasher = Argon2PasswordHasher()
    settings = get_settings()
    google_http = httpx.AsyncClient(timeout=GOOGLE_TIMEOUT_SECONDS)
    app.state.oidc_provider = GoogleOidcProvider(
        client_id=settings.google.client_id,
        client_secret=settings.google.client_secret.get_secret_value(),
        redirect_uri=settings.app.public_base_url + API_V1_PREFIX + GOOGLE_CALLBACK_PATH,
        http=google_http,
        jwks=JwksCache(google_http),
    )
    try:
        yield
    finally:
        try:
            await dispose_engine()
        except Exception as exc:
            logger.warning("app.dispose_engine_unavailable", error=str(exc))
        try:
            await close_redis()
        except Exception as exc:
            logger.warning("app.redis_close_unavailable", error=str(exc))
        try:
            await google_http.aclose()
        except Exception as exc:
            logger.warning("app.google_http_close_unavailable", error=str(exc))


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
    api_router.include_router(identity_router)
    return app


app = create_app()
