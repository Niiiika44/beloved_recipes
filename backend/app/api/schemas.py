from typing import Any

from pydantic import BaseModel, Field

BLANK_TYPE = "about:blank"
PROBLEM_TYPE_PATH = "/problems/"
AUTHENTICATE_HEADER = "Cookie"


class ProblemDetail(BaseModel):
    type: str = BLANK_TYPE
    title: str = Field(..., description="Problem title")
    status: int = Field(..., description="HTTP code")
    detail: str | None = Field(None, description="Problem detail")
    instance: str | None = Field(None, description="Request path")
    request_id: str | None = Field(None, description="Request id")
    errors: list[dict[str, Any]] | None = Field(None, description="Validation errors")
