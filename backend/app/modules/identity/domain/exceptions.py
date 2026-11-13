from collections.abc import Mapping
from typing import ClassVar, Literal

from app.core.exceptions import (
    ConflictError,
    FieldError,
    InvalidInputError,
    NotAuthenticatedError,
    PermissionDeniedError,
)

NicknameProblem = Literal["too_short", "too_long", "bad_characters", "bad_dots", "reserved"]
PasswordProblem = Literal["blank", "too_short", "too_long", "breached"]
DisplayNameProblem = Literal["empty", "too_long", "bad_characters"]


class InvalidSessionError(NotAuthenticatedError):
    def __init__(self) -> None:
        super().__init__("Session is missing or invalid")


class InvalidNicknameError(FieldError):
    code = "nickname_invalid"
    field = "nickname"

    messages: ClassVar[Mapping[NicknameProblem, str]] = {
        "too_short": "Nickname is too short",
        "too_long": "Nickname is too long",
        "bad_characters": "Nickname may contain only latin letters, digits, '_' and '.'",
        "bad_dots": "Nickname may not start or end with a dot or contain two dots in a row",
        "reserved": "Nickname is reserved",
    }

    def __init__(self, reason: NicknameProblem):
        super().__init__(self.messages[reason], reason)


class NicknameTakenError(ConflictError):
    code = "nickname_taken"

    def __init__(self) -> None:
        super().__init__("Nickname is already taken")


class NicknameRequiredError(PermissionDeniedError):
    code = "nickname_required"

    def __init__(self) -> None:
        super().__init__("Choose a nickname first")


class WeakPasswordError(FieldError):
    code = "password_weak"
    field = "password"

    messages: ClassVar[Mapping[PasswordProblem, str]] = {
        "blank": "Password consists only of whitespace",
        "too_short": "Password is too short",
        "too_long": "Password is too long",
        "breached": "Password appears in known data breaches",
    }

    def __init__(self, reason: PasswordProblem):
        super().__init__(self.messages[reason], reason)


class InvalidDisplayNameError(FieldError):
    code = "display_name_invalid"
    field = "display_name"

    messages: ClassVar[Mapping[DisplayNameProblem, str]] = {
        "empty": "Display name is empty",
        "too_long": "Display name is too long",
        "bad_characters": "Display name contains control characters",
    }

    def __init__(self, reason: DisplayNameProblem):
        super().__init__(self.messages[reason], reason)


class InvalidCredentialsError(NotAuthenticatedError):
    code = "invalid_credentials"

    def __init__(self) -> None:
        super().__init__("Email or password is incorrect")


class EmailNotVerifiedError(PermissionDeniedError):
    code = "email_not_verified"

    def __init__(self) -> None:
        super().__init__("Email is not verified")


class InvalidTokenError(InvalidInputError):
    code = "token_invalid"

    def __init__(self) -> None:
        super().__init__("Link is invalid or expired")


class PasswordNotSetError(ConflictError):
    code = "password_not_set"

    def __init__(self) -> None:
        super().__init__("Password is not set; use password reset to create one")


class EmailConflictError(ConflictError):
    code = "email_conflict"

    def __init__(self) -> None:
        super().__init__("Email is already used by another account")
