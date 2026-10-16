from app.core.exceptions import NotAuthenticatedError


class InvalidSessionError(NotAuthenticatedError):
    def __init__(self) -> None:
        super().__init__("Session is missing or invalid")
