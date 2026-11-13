from collections.abc import Mapping
from datetime import timedelta
from typing import get_args

import pytest

from app.api.exceptions import spec_for
from app.core.exceptions import (
    AppError,
    ConflictError,
    FieldError,
    InvalidInputError,
    NotAuthenticatedError,
    PermissionDeniedError,
)
from app.modules.identity.domain.enums import LoginMethod, TokenPurpose
from app.modules.identity.domain.exceptions import (
    DisplayNameProblem,
    EmailConflictError,
    EmailNotVerifiedError,
    InvalidCredentialsError,
    InvalidDisplayNameError,
    InvalidNicknameError,
    InvalidTokenError,
    NicknameProblem,
    NicknameRequiredError,
    NicknameTakenError,
    PasswordNotSetError,
    PasswordProblem,
    WeakPasswordError,
)
from app.modules.identity.domain.nicknames import (
    NICKNAME_QUARANTINE,
    RESERVED_NICKNAMES,
    normalize_nickname,
)
from app.modules.identity.domain.passwords import normalize_password
from app.modules.identity.domain.profile import normalize_display_name
from app.modules.identity.domain.redirects import safe_next


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("anna", "anna"),
        ("  Chef.Anna ", "chef.anna"),
        ("ＡＮＮＡ", "anna"),
        ("cook_2026", "cook_2026"),
        ("abc", "abc"),
        ("a" * 30, "a" * 30),
        ("a.b.c", "a.b.c"),
    ],
)
def test_nickname_is_normalized(raw: str, expected: str) -> None:
    assert normalize_nickname(raw) == expected


@pytest.mark.parametrize(
    ("raw", "reason"),
    [
        ("ab", "too_short"),
        ("   ", "too_short"),
        ("a" * 31, "too_long"),
        ("анна", "bad_characters"),
        ("a-b", "bad_characters"),
        ("an na", "bad_characters"),
        ("İstanbul", "bad_characters"),
        ("anna!", "bad_characters"),
        (".anna", "bad_dots"),
        ("anna.", "bad_dots"),
        ("an..na", "bad_dots"),
        ("admin", "reserved"),
        ("Admin", "reserved"),
        (" ROOT ", "reserved"),
    ],
)
def test_nickname_is_rejected_with_reason(raw: str, reason: str) -> None:
    with pytest.raises(InvalidNicknameError) as excinfo:
        normalize_nickname(raw)

    assert excinfo.value.reason == reason
    assert excinfo.value.field == "nickname"


def test_reserved_nicknames_match_the_decision_log() -> None:
    assert (
        frozenset(
            {
                "admin",
                "administrator",
                "api",
                "auth",
                "help",
                "me",
                "moderator",
                "null",
                "root",
                "settings",
                "support",
                "system",
                "undefined",
                "www",
            }
        )
        == RESERVED_NICKNAMES
    )


def test_nickname_quarantine_lasts_thirty_days() -> None:
    assert timedelta(days=30) == NICKNAME_QUARANTINE


@pytest.mark.parametrize(
    "raw",
    [
        "/",
        "/recipes",
        "/recipes?id=1&tab=ingredients",
        "/recipes#steps",
        "/%2F%2Fevil.com",
        "/https://evil.com",
        "/" + "a" * 2047,
    ],
)
def test_same_site_path_is_kept(raw: str) -> None:
    assert safe_next(raw) == raw


@pytest.mark.parametrize(
    "raw",
    [
        None,
        "",
        "recipes",
        "//evil.com",
        "///evil.com",
        "/\\evil.com",
        "/recipes\\..\\evil",
        "https://evil.com",
        "javascript:alert(1)",
        "/\t/evil.com",
        "/\n/evil.com",
        "/x\r",
        "/x‮",
        "/" + "a" * 2048,
    ],
)
def test_unsafe_next_falls_back_to_root(raw: str | None) -> None:
    assert safe_next(raw) == "/"


def test_password_keeps_surrounding_spaces() -> None:
    assert normalize_password(" secret1 ") == " secret1 "


def test_password_composed_and_decomposed_forms_match() -> None:
    assert normalize_password("café-1234") == normalize_password("café-1234")


def test_password_length_is_counted_after_normalization() -> None:
    assert normalize_password("ﬁ" * 4) == "fi" * 4


@pytest.mark.parametrize("length", [8, 128])
def test_password_at_length_limit_is_accepted(length: int) -> None:
    assert len(normalize_password("p" * length)) == length


@pytest.mark.parametrize(("length", "reason"), [(7, "too_short"), (129, "too_long")])
def test_password_beyond_length_limit_is_rejected(length: int, reason: str) -> None:
    with pytest.raises(WeakPasswordError) as excinfo:
        normalize_password("p" * length)

    assert excinfo.value.reason == reason
    assert excinfo.value.field == "password"


@pytest.mark.parametrize(
    "raw",
    ["", " ", " " * 8, " " * 129, "\t" * 10, " \n \r\n ", " " * 8, "　" * 8],
)
def test_whitespace_only_password_is_blank(raw: str) -> None:
    with pytest.raises(WeakPasswordError) as excinfo:
        normalize_password(raw)

    assert excinfo.value.reason == "blank"


def test_password_with_inner_spaces_is_accepted() -> None:
    assert normalize_password("мама мыла раму") == "мама мыла раму"


def test_rejected_password_is_not_echoed() -> None:
    with pytest.raises(WeakPasswordError) as excinfo:
        normalize_password("hunter2")

    assert "hunter2" not in str(excinfo.value)
    assert "hunter2" not in excinfo.value.message


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("  Анна  ", "Анна"),
        ("Шеф \U0001f469‍\U0001f373", "Шеф \U0001f469‍\U0001f373"),
        ("я" * 100, "я" * 100),
    ],
)
def test_display_name_is_normalized(raw: str, expected: str) -> None:
    assert normalize_display_name(raw) == expected


@pytest.mark.parametrize(
    ("raw", "reason"),
    [
        ("", "empty"),
        ("   ", "empty"),
        ("я" * 101, "too_long"),
        ("Анна\x00", "bad_characters"),
        ("Анна\nВторая", "bad_characters"),
        ("Анна‮анна", "bad_characters"),
    ],
)
def test_display_name_is_rejected_with_reason(raw: str, reason: str) -> None:
    with pytest.raises(InvalidDisplayNameError) as excinfo:
        normalize_display_name(raw)

    assert excinfo.value.reason == reason
    assert excinfo.value.field == "display_name"


@pytest.mark.parametrize(
    ("messages", "problems"),
    [
        (InvalidNicknameError.messages, NicknameProblem),
        (WeakPasswordError.messages, PasswordProblem),
        (InvalidDisplayNameError.messages, DisplayNameProblem),
    ],
)
def test_every_reason_has_a_message(messages: Mapping[str, str], problems: object) -> None:
    assert set(messages) == set(get_args(problems))


@pytest.mark.parametrize(
    ("error", "category", "code", "status"),
    [
        (InvalidNicknameError("too_short"), FieldError, "nickname_invalid", 422),
        (NicknameTakenError(), ConflictError, "nickname_taken", 409),
        (NicknameRequiredError(), PermissionDeniedError, "nickname_required", 403),
        (WeakPasswordError("breached"), FieldError, "password_weak", 422),
        (InvalidDisplayNameError("empty"), FieldError, "display_name_invalid", 422),
        (InvalidCredentialsError(), NotAuthenticatedError, "invalid_credentials", 401),
        (EmailNotVerifiedError(), PermissionDeniedError, "email_not_verified", 403),
        (InvalidTokenError(), InvalidInputError, "token_invalid", 422),
        (PasswordNotSetError(), ConflictError, "password_not_set", 409),
        (EmailConflictError(), ConflictError, "email_conflict", 409),
    ],
)
def test_identity_error_has_category_code_and_status(
    error: AppError, category: type[AppError], code: str, status: int
) -> None:
    assert isinstance(error, category)
    assert error.code == code
    assert error.message
    assert spec_for(error).status == status


def test_field_error_is_invalid_input() -> None:
    assert issubclass(FieldError, InvalidInputError)


def test_token_purposes() -> None:
    assert [purpose.value for purpose in TokenPurpose] == ["email_confirm", "password_reset"]


def test_login_methods() -> None:
    assert [method.value for method in LoginMethod] == ["google", "password"]
