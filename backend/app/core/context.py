import structlog

NO_REQUEST_ID = "-"


def get_request_id() -> str:
    return str(structlog.contextvars.get_contextvars().get("request_id", NO_REQUEST_ID))
