from typing import ClassVar


class AppError(Exception):
    """Base class for all domain-level exceptions."""

    code: ClassVar[str | None] = None

    def __init__(self, message: str):
        self.message = message
        super().__init__(self.message)


class NotFoundError(AppError):
    pass


class PermissionDeniedError(AppError):
    pass


class ConflictError(AppError):
    pass


class InvalidInputError(AppError):
    pass


class FieldError(InvalidInputError):
    """Invalid value of one input field; reason names the rule it broke."""

    field: ClassVar[str]

    def __init__(self, message: str, reason: str):
        super().__init__(message)
        self.reason = reason


class NotAuthenticatedError(AppError):
    pass


class DependencyUnavailableError(AppError):
    pass
