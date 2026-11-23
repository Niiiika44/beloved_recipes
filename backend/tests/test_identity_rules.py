import dataclasses
import hashlib
import hmac
import uuid
from collections.abc import Mapping
from datetime import UTC, datetime, timedelta, timezone
from typing import Any, get_args

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
from app.modules.identity.domain.emails import email_fingerprint
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
from app.modules.identity.domain.limits import (
    NICKNAME_CHANGE_LIMIT,
    NICKNAME_CHECK_LIMIT,
    REGISTRATION_EMAIL_LIMIT,
    REGISTRATION_IP_LIMIT,
    RESEND_CONFIRMATION_EMAIL_LIMIT,
    RESEND_CONFIRMATION_IP_LIMIT,
    RateLimit,
)
from app.modules.identity.domain.mail import (
    EMAIL_CONFIRM_TOKEN_TTL,
    FAILED_MAIL_RETENTION,
    MAIL_MAX_ATTEMPTS,
    retry_delay,
)
from app.modules.identity.domain.nicknames import (
    NICKNAME_QUARANTINE,
    RESERVED_NICKNAMES,
    is_quarantined,
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


RELEASED_AT = datetime(2026, 11, 1, 12, 0, tzinfo=UTC)
ASKER = uuid.UUID("01900000-0000-7000-8000-000000000001")
FORMER_OWNER = uuid.UUID("01900000-0000-7000-8000-000000000002")


def _quarantined(released_by: uuid.UUID | None, age: timedelta) -> bool:
    return is_quarantined(
        released_by=released_by,
        released_at=RELEASED_AT,
        user_id=ASKER,
        now=RELEASED_AT + age,
    )


@pytest.mark.parametrize(
    "age",
    [
        timedelta(0),
        timedelta(seconds=1),
        timedelta(days=29),
        timedelta(days=30) - timedelta(seconds=1),
    ],
)
def test_someone_elses_released_nickname_is_quarantined(age: timedelta) -> None:
    assert _quarantined(FORMER_OWNER, age) is True


@pytest.mark.parametrize(
    "age", [timedelta(days=30), timedelta(days=30, seconds=1), timedelta(days=365)]
)
def test_quarantine_ends_after_thirty_days(age: timedelta) -> None:
    assert _quarantined(FORMER_OWNER, age) is False


@pytest.mark.parametrize("age", [timedelta(0), timedelta(days=1), timedelta(days=31)])
def test_own_released_nickname_is_never_quarantined(age: timedelta) -> None:
    assert _quarantined(ASKER, age) is False


def test_nickname_of_deleted_account_is_quarantined() -> None:
    assert _quarantined(None, timedelta(days=1)) is True


def test_nickname_of_deleted_account_is_free_after_thirty_days() -> None:
    assert _quarantined(None, timedelta(days=30)) is False


def test_quarantine_compares_moments_across_time_zones() -> None:
    moscow = datetime(2026, 11, 1, 15, 0, tzinfo=timezone(timedelta(hours=3)))

    assert is_quarantined(
        released_by=FORMER_OWNER,
        released_at=RELEASED_AT,
        user_id=ASKER,
        now=moscow + timedelta(days=30) - timedelta(seconds=1),
    )


def test_quarantine_arguments_are_keyword_only() -> None:
    call: Any = is_quarantined

    with pytest.raises(TypeError):
        call(FORMER_OWNER, RELEASED_AT, ASKER, RELEASED_AT)


def test_nickname_change_limit_is_three_per_day() -> None:
    assert RateLimit(limit=3, window=timedelta(days=1)) == NICKNAME_CHANGE_LIMIT


def test_nickname_check_limit_is_sixty_per_minute() -> None:
    assert RateLimit(limit=60, window=timedelta(minutes=1)) == NICKNAME_CHECK_LIMIT


def test_registration_email_limit_is_five_per_hour() -> None:
    assert RateLimit(limit=5, window=timedelta(hours=1)) == REGISTRATION_EMAIL_LIMIT


def test_registration_ip_limit_is_twenty_per_hour() -> None:
    assert RateLimit(limit=20, window=timedelta(hours=1)) == REGISTRATION_IP_LIMIT


def test_resend_confirmation_email_limit_is_five_per_hour() -> None:
    assert RateLimit(limit=5, window=timedelta(hours=1)) == RESEND_CONFIRMATION_EMAIL_LIMIT


def test_resend_confirmation_ip_limit_is_twenty_per_hour() -> None:
    assert RateLimit(limit=20, window=timedelta(hours=1)) == RESEND_CONFIRMATION_IP_LIMIT


def test_confirmation_link_lives_a_day() -> None:
    assert timedelta(hours=24) == EMAIL_CONFIRM_TOKEN_TTL


def test_mail_gives_up_after_eight_attempts() -> None:
    assert MAIL_MAX_ATTEMPTS == 8


def test_failed_mail_is_kept_for_thirty_days() -> None:
    assert timedelta(days=30) == FAILED_MAIL_RETENTION


@pytest.mark.parametrize(
    ("attempts", "delay"),
    [
        (1, timedelta(seconds=30)),
        (2, timedelta(minutes=1)),
        (3, timedelta(minutes=2)),
        (7, timedelta(minutes=32)),
        (8, timedelta(hours=1)),
        (20, timedelta(hours=1)),
    ],
)
def test_retry_delay_doubles_up_to_an_hour(attempts: int, delay: timedelta) -> None:
    assert retry_delay(attempts) == delay


FINGERPRINT_SECRET = b"fingerprint-secret"


def test_email_fingerprint_is_hmac_sha256_of_lowercased_email() -> None:
    expected = hmac.new(FINGERPRINT_SECRET, b"anna@example.org", hashlib.sha256).hexdigest()

    assert email_fingerprint("Anna@Example.ORG", FINGERPRINT_SECRET) == expected


@pytest.mark.parametrize("email", ["anna@example.org", "ANNA@EXAMPLE.ORG", "Anna@example.Org"])
def test_email_fingerprint_ignores_case(email: str) -> None:
    assert email_fingerprint(email, FINGERPRINT_SECRET) == email_fingerprint(
        "anna@example.org", FINGERPRINT_SECRET
    )


def test_email_fingerprint_depends_on_the_secret() -> None:
    assert email_fingerprint("anna@example.org", b"one") != email_fingerprint(
        "anna@example.org", b"two"
    )


def test_email_fingerprint_differs_between_emails() -> None:
    assert email_fingerprint("anna@example.org", FINGERPRINT_SECRET) != email_fingerprint(
        "boris@example.org", FINGERPRINT_SECRET
    )


def test_email_fingerprint_cannot_be_matched_against_plain_sha256() -> None:
    fingerprint = email_fingerprint("anna@example.org", FINGERPRINT_SECRET)

    assert fingerprint != hashlib.sha256(b"anna@example.org").hexdigest()
    assert "anna" not in fingerprint
    assert len(fingerprint) == 64


def test_rate_limit_is_immutable() -> None:
    rule: Any = NICKNAME_CHANGE_LIMIT

    with pytest.raises(dataclasses.FrozenInstanceError):
        rule.limit = 100


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


@pytest.mark.parametrize(
    "raw",
    ["correct horse \ud800", "\udfff" * 10, "\ud83d" + " battery staple", "\ud800"],
    ids=["high_inside", "low_only", "unpaired_high_first", "too_short_too"],
)
def test_password_with_lone_surrogate_has_bad_characters(raw: str) -> None:
    with pytest.raises(WeakPasswordError) as excinfo:
        normalize_password(raw)

    assert excinfo.value.reason == "bad_characters"
    assert excinfo.value.field == "password"


@pytest.mark.parametrize(
    "raw",
    ["пароль 😀 эмодзи", "𝕔𝕠𝕣𝕣𝕖𝕔𝕥 horse", "tab\tinside password", "zero\u200dwidth joiner"],
    ids=["emoji", "astral_letters", "tab", "zwj"],
)
def test_password_of_valid_text_survives_encoding(raw: str) -> None:
    normalize_password(raw).encode()


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
