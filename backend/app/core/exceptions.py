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


class NotAuthenticatedError(AppError):
    pass


class DependencyUnavailableError(AppError):
    pass
