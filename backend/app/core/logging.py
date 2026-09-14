import logging.config
import sys

import structlog
from structlog.dev import ConsoleRenderer
from structlog.processors import JSONRenderer
from structlog.typing import Processor

from app.core.config import get_settings


def get_renderer(app_env: str) -> JSONRenderer | ConsoleRenderer:
    if app_env == "local":
        return ConsoleRenderer()
    return JSONRenderer(ensure_ascii=False)


def configure_logging() -> None:
    settings = get_settings()

    structlog_processors: list[Processor] = [
        structlog.contextvars.merge_contextvars,
        structlog.processors.add_log_level,
        structlog.processors.TimeStamper(fmt="iso", utc=True),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
    ]

    structlog.configure(
        processors=[*structlog_processors, structlog.stdlib.ProcessorFormatter.wrap_for_formatter],
        logger_factory=structlog.stdlib.LoggerFactory(),
        cache_logger_on_first_use=True,
    )

    config = {
        "version": 1,
        "disable_existing_loggers": False,
        "formatters": {
            "structured": {
                "()": "structlog.stdlib.ProcessorFormatter",
                "foreign_pre_chain": structlog_processors,
                "processors": [
                    structlog.stdlib.ProcessorFormatter.remove_processors_meta,
                    get_renderer(settings.app.env),
                ],
            }
        },
        "handlers": {
            "default": {
                "class": "logging.StreamHandler",
                "formatter": "structured",
                "stream": sys.stdout,
            }
        },
        "root": {"handlers": ["default"], "level": settings.app.log_level},
        "loggers": {
            "uvicorn": {"handlers": [], "propagate": True},
            "uvicorn.error": {"handlers": [], "propagate": True},
            "uvicorn.access": {"handlers": [], "propagate": False},
        },
    }

    logging.config.dictConfig(config)
