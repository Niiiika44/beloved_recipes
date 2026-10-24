import os
from pathlib import Path
from urllib.parse import unquote, urlsplit

import pytest
from pydantic import ValidationError

from app.core.config import Settings, get_settings

SECTIONS = ("APP", "DB", "REDIS", "SECURITY", "SESSION", "GOOGLE", "MAIL")

REQUIRED_ENV = {
    "DB__USER": "recipes",
    "DB__PASSWORD": "db-secret",
    "DB__NAME": "recipes",
    "REDIS__PASSWORD": "redis-secret",
    "SECURITY__SECRET_KEY": "s" * 32,
    "GOOGLE__CLIENT_ID": "123456789012-abc123def456.apps.googleusercontent.com",
    "GOOGLE__CLIENT_SECRET": "google-secret",
}

PROD_ENV = {
    "APP__ENV": "prod",
    "SECURITY__SECRET_KEY": "k" * 32,
    "SESSION__COOKIE_NAME": "__Host-session",
    "SESSION__COOKIE_SECURE": "true",
    "APP__PUBLIC_BASE_URL": "https://recipes.ru",
    "MAIL__TLS": "tls",
    "MAIL__SENDER_ADDRESS": "no-reply@recipes.ru",
}

TRICKY_PASSWORD = "p@ss/wo rd#1:2?3"

ENV_EXAMPLE = Path(__file__).resolve().parents[2] / "infra" / ".env.example"


@pytest.fixture(autouse=True)
def _isolated_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for key in list(os.environ):
        if key.split("__", 1)[0] in SECTIONS:
            monkeypatch.delenv(key, raising=False)
    get_settings.cache_clear()


def _build(monkeypatch: pytest.MonkeyPatch, **overrides: str) -> Settings:
    for key, value in (REQUIRED_ENV | overrides).items():
        monkeypatch.setenv(key, value)
    return Settings(_env_file=None)


def test_missing_required_values_are_reported_together(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with pytest.raises(ValidationError) as excinfo:
        Settings(_env_file=None)

    reported = {error["loc"][0] for error in excinfo.value.errors()}
    assert reported == {"db", "redis", "security", "google"}


def test_defaults_apply_to_optional_values(monkeypatch: pytest.MonkeyPatch) -> None:
    settings = _build(monkeypatch)

    assert settings.app.env == "local"
    assert settings.app.is_prod is False
    assert settings.db.host == "127.0.0.1"
    assert settings.db.port == 5432
    assert settings.redis.db == 0


def test_works_without_env_file(monkeypatch: pytest.MonkeyPatch) -> None:
    settings = _build(monkeypatch)

    assert settings.db.user == "recipes"


def test_env_file_is_read_when_present(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    env_file = tmp_path / ".env"
    env_file.write_text(
        "\n".join(f"{key}={value}" for key, value in REQUIRED_ENV.items()),
        encoding="utf-8",
    )

    settings = Settings(_env_file=env_file)

    assert settings.db.name == "recipes"


def test_typo_inside_known_section_is_rejected(tmp_path: Path) -> None:
    env_file = tmp_path / ".env"
    lines = [f"{key}={value}" for key, value in REQUIRED_ENV.items()]
    lines.append("DB__PORTT=9999")
    env_file.write_text("\n".join(lines), encoding="utf-8")

    with pytest.raises(ValidationError):
        Settings(_env_file=env_file)


def test_infrastructure_keys_are_ignored(tmp_path: Path) -> None:
    env_file = tmp_path / ".env"
    lines = [f"{key}={value}" for key, value in REQUIRED_ENV.items()]
    lines += ["NEO4J_PASSWORD=whatever", "MINIO_PORT=9002", "KAFKA_PORT=29092"]
    env_file.write_text("\n".join(lines), encoding="utf-8")

    settings = Settings(_env_file=env_file)

    assert settings.db.name == "recipes"


def test_secrets_are_masked_in_repr(monkeypatch: pytest.MonkeyPatch) -> None:
    settings = _build(monkeypatch, DB__PASSWORD="hunter2")

    rendered = repr(settings)

    assert "hunter2" not in rendered
    assert "**********" in rendered


def test_dsn_is_absent_from_serialised_form(monkeypatch: pytest.MonkeyPatch) -> None:
    settings = _build(monkeypatch, DB__PASSWORD="hunter2")

    assert "dsn" not in settings.model_dump()
    assert "hunter2" not in repr(settings.db)


def test_database_dsn_survives_special_characters(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = _build(monkeypatch, DB__USER="ne mo", DB__PASSWORD=TRICKY_PASSWORD)

    parts = urlsplit(settings.db.dsn)

    assert parts.scheme == "postgresql+asyncpg"
    assert parts.hostname == "127.0.0.1"
    assert parts.port == 5432
    assert parts.path == "/recipes"
    assert unquote(parts.username or "") == "ne mo"
    assert unquote(parts.password or "") == TRICKY_PASSWORD


def test_redis_dsn_survives_special_characters(monkeypatch: pytest.MonkeyPatch) -> None:
    settings = _build(monkeypatch, REDIS__PASSWORD=TRICKY_PASSWORD, REDIS__DB="3")

    parts = urlsplit(settings.redis.dsn)

    assert parts.scheme == "redis"
    assert parts.port == 6379
    assert parts.path == "/3"
    assert unquote(parts.password or "") == TRICKY_PASSWORD


def test_unknown_app_env_is_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(ValidationError):
        _build(monkeypatch, APP__ENV="prd")


def test_prod_rejects_short_secret_key(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(ValidationError, match="SECRET_KEY"):
        _build(monkeypatch, **(PROD_ENV | {"SECURITY__SECRET_KEY": "short"}))


def test_prod_accepts_long_secret_key(monkeypatch: pytest.MonkeyPatch) -> None:
    settings = _build(monkeypatch, **PROD_ENV)

    assert settings.app.is_prod is True


def test_settings_are_immutable(monkeypatch: pytest.MonkeyPatch) -> None:
    settings = _build(monkeypatch)

    with pytest.raises(ValidationError):
        settings.db.port = 6000  # type: ignore[misc]


def test_get_settings_returns_cached_instance(monkeypatch: pytest.MonkeyPatch) -> None:
    for key, value in REQUIRED_ENV.items():
        monkeypatch.setenv(key, value)

    first = get_settings()
    second = get_settings()

    assert first is second

    get_settings.cache_clear()
    monkeypatch.setenv("DB__NAME", "other")

    assert get_settings().db.name == "other"


def test_session_section_is_optional_and_has_defaults(monkeypatch: pytest.MonkeyPatch) -> None:
    settings = _build(monkeypatch)

    assert settings.session.cookie_name == "session"
    assert settings.session.cookie_secure is False
    assert settings.session.idle_ttl_seconds == 1_209_600
    assert settings.session.absolute_ttl_seconds == 2_592_000
    assert settings.session.operation_timeout_seconds == 1.0


def test_session_values_are_read_from_env(monkeypatch: pytest.MonkeyPatch) -> None:
    settings = _build(
        monkeypatch,
        SESSION__COOKIE_NAME="sid",
        SESSION__IDLE_TTL_SECONDS="60",
        SESSION__ABSOLUTE_TTL_SECONDS="120",
        SESSION__OPERATION_TIMEOUT_SECONDS="0.5",
    )

    assert settings.session.cookie_name == "sid"
    assert settings.session.idle_ttl_seconds == 60
    assert settings.session.absolute_ttl_seconds == 120
    assert settings.session.operation_timeout_seconds == 0.5


def test_prod_rejects_insecure_session_cookie(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(ValidationError, match="COOKIE_SECURE"):
        _build(
            monkeypatch,
            **(PROD_ENV | {"SESSION__COOKIE_NAME": "session", "SESSION__COOKIE_SECURE": "false"}),
        )


def test_prod_requires_host_prefixed_cookie_name(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(ValidationError, match="COOKIE_NAME"):
        _build(monkeypatch, **(PROD_ENV | {"SESSION__COOKIE_NAME": "session"}))


def test_prod_rejects_secure_prefix_instead_of_host_prefix(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with pytest.raises(ValidationError, match="COOKIE_NAME"):
        _build(monkeypatch, **(PROD_ENV | {"SESSION__COOKIE_NAME": "__Secure-session"}))


@pytest.mark.parametrize("name", ["__Host-session", "__Secure-session"])
def test_prefixed_cookie_requires_secure_in_any_env(
    monkeypatch: pytest.MonkeyPatch, name: str
) -> None:
    with pytest.raises(ValidationError, match="COOKIE_NAME"):
        _build(monkeypatch, SESSION__COOKIE_NAME=name, SESSION__COOKIE_SECURE="false")


@pytest.mark.parametrize("name", ["__Host-session", "__Secure-session"])
def test_prefixed_secure_cookie_is_allowed_locally(
    monkeypatch: pytest.MonkeyPatch, name: str
) -> None:
    settings = _build(monkeypatch, SESSION__COOKIE_NAME=name, SESSION__COOKIE_SECURE="true")

    assert settings.session.cookie_name == name


def test_absolute_ttl_shorter_than_idle_is_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(ValidationError, match="ABSOLUTE_TTL"):
        _build(monkeypatch, SESSION__IDLE_TTL_SECONDS="100", SESSION__ABSOLUTE_TTL_SECONDS="99")


def test_absolute_ttl_equal_to_idle_is_allowed(monkeypatch: pytest.MonkeyPatch) -> None:
    settings = _build(
        monkeypatch, SESSION__IDLE_TTL_SECONDS="100", SESSION__ABSOLUTE_TTL_SECONDS="100"
    )

    assert settings.session.absolute_ttl_seconds == 100


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("SESSION__IDLE_TTL_SECONDS", "0"),
        ("SESSION__IDLE_TTL_SECONDS", "-1"),
        ("SESSION__ABSOLUTE_TTL_SECONDS", "0"),
        ("SESSION__ABSOLUTE_TTL_SECONDS", "-1"),
        ("SESSION__OPERATION_TIMEOUT_SECONDS", "0"),
        ("SESSION__OPERATION_TIMEOUT_SECONDS", "-0.5"),
    ],
)
def test_non_positive_session_durations_are_rejected(
    monkeypatch: pytest.MonkeyPatch, key: str, value: str
) -> None:
    with pytest.raises(ValidationError):
        _build(monkeypatch, **{key: value})


def test_typo_inside_session_section_is_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(ValidationError):
        _build(monkeypatch, SESSION__COOKIE_NAMEE="sid")


def test_public_base_url_defaults_to_local_origin(monkeypatch: pytest.MonkeyPatch) -> None:
    settings = _build(monkeypatch)

    assert settings.app.public_base_url == "http://localhost:8000"


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("http://localhost:8000/", "http://localhost:8000"),
        ("http://localhost:5173", "http://localhost:5173"),
        ("HTTPS://Recipes.RU:443", "https://recipes.ru"),
    ],
)
def test_public_base_url_is_normalised_to_origin(
    monkeypatch: pytest.MonkeyPatch, raw: str, expected: str
) -> None:
    settings = _build(monkeypatch, APP__PUBLIC_BASE_URL=raw)

    assert settings.app.public_base_url == expected


@pytest.mark.parametrize(
    "raw",
    [
        "http://localhost:8000/app",
        "http://localhost:8000?next=1",
        "http://localhost:8000#top",
        "http://user@localhost:8000",
        "http://:secret@localhost:8000",
        "localhost:8000",
        "ftp://localhost:8000",
    ],
)
def test_public_base_url_must_be_an_origin(monkeypatch: pytest.MonkeyPatch, raw: str) -> None:
    with pytest.raises(ValidationError, match="public_base_url"):
        _build(monkeypatch, APP__PUBLIC_BASE_URL=raw)


def test_prod_rejects_plain_http_public_base_url(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(ValidationError, match="PUBLIC_BASE_URL"):
        _build(monkeypatch, **(PROD_ENV | {"APP__PUBLIC_BASE_URL": "http://recipes.ru"}))


def test_missing_google_client_secret_is_reported_by_name(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("GOOGLE__CLIENT_ID", REQUIRED_ENV["GOOGLE__CLIENT_ID"])

    with pytest.raises(ValidationError) as excinfo:
        Settings(_env_file=None)

    locations = {error["loc"] for error in excinfo.value.errors()}
    assert ("google", "client_secret") in locations
    assert ("google", "client_id") not in locations


def test_google_client_id_keeps_google_format(monkeypatch: pytest.MonkeyPatch) -> None:
    settings = _build(monkeypatch)

    assert settings.google.client_id == REQUIRED_ENV["GOOGLE__CLIENT_ID"]


def test_google_client_secret_is_masked_in_repr(monkeypatch: pytest.MonkeyPatch) -> None:
    settings = _build(monkeypatch, GOOGLE__CLIENT_SECRET="hunter2")

    assert "hunter2" not in repr(settings)
    assert settings.google.client_secret.get_secret_value() == "hunter2"


def test_typo_inside_google_section_is_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(ValidationError):
        _build(monkeypatch, GOOGLE__CLIENT_IDD="x")


def test_mail_section_defaults_target_local_mailpit(monkeypatch: pytest.MonkeyPatch) -> None:
    settings = _build(monkeypatch)

    assert settings.mail.host == "127.0.0.1"
    assert settings.mail.port == 1025
    assert settings.mail.tls == "none"
    assert settings.mail.username is None
    assert settings.mail.password is None
    assert settings.mail.sender_name == "Beloved Recipes"
    assert settings.mail.sender_address == "no-reply@example.com"


def test_mail_credentials_are_accepted_together(monkeypatch: pytest.MonkeyPatch) -> None:
    settings = _build(monkeypatch, MAIL__USERNAME="mailer", MAIL__PASSWORD="hunter2")

    assert settings.mail.username == "mailer"
    assert settings.mail.password is not None
    assert settings.mail.password.get_secret_value() == "hunter2"
    assert "hunter2" not in repr(settings)


def test_mail_password_without_username_is_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(ValidationError, match="MAIL__USERNAME"):
        _build(monkeypatch, MAIL__PASSWORD="hunter2")


def test_mail_username_without_password_is_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(ValidationError, match="MAIL__PASSWORD"):
        _build(monkeypatch, MAIL__USERNAME="mailer")


def test_empty_mail_credentials_count_as_unset(monkeypatch: pytest.MonkeyPatch) -> None:
    settings = _build(monkeypatch, MAIL__USERNAME="", MAIL__PASSWORD="")

    assert settings.mail.username is None
    assert settings.mail.password is None


def test_empty_lines_in_env_file_count_as_unset(tmp_path: Path) -> None:
    env_file = tmp_path / ".env"
    lines = [f"{key}={value}" for key, value in REQUIRED_ENV.items()]
    lines += ["MAIL__USERNAME=", "MAIL__PASSWORD="]
    env_file.write_text("\n".join(lines), encoding="utf-8")

    settings = Settings(_env_file=env_file)

    assert settings.mail.username is None
    assert settings.mail.password is None


def test_empty_secret_key_is_reported_as_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(ValidationError) as excinfo:
        _build(monkeypatch, SECURITY__SECRET_KEY="")

    assert {error["loc"] for error in excinfo.value.errors()} == {("security",)}


def test_unknown_mail_tls_mode_is_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(ValidationError, match="tls"):
        _build(monkeypatch, MAIL__TLS="starttls")


def test_typo_inside_mail_section_is_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(ValidationError):
        _build(monkeypatch, MAIL__HOSTT="smtp.recipes.ru")


@pytest.mark.parametrize(
    "address",
    [
        "no-reply",
        "no reply@recipes.ru",
        "no-reply@@recipes.ru",
        "a@b@recipes.ru",
        "no-reply@recipes.ru\r\nBcc: victim@recipes.ru",
        "no-reply@localhost",
        "no-reply@mailpit.test",
    ],
)
def test_invalid_sender_address_is_rejected(monkeypatch: pytest.MonkeyPatch, address: str) -> None:
    with pytest.raises(ValidationError, match="sender_address"):
        _build(monkeypatch, MAIL__SENDER_ADDRESS=address)


def test_sender_address_domain_is_normalised(monkeypatch: pytest.MonkeyPatch) -> None:
    settings = _build(monkeypatch, MAIL__SENDER_ADDRESS="no-reply@Recipes.RU")

    assert settings.mail.sender_address == "no-reply@recipes.ru"


def test_sender_name_is_stripped(monkeypatch: pytest.MonkeyPatch) -> None:
    settings = _build(monkeypatch, MAIL__SENDER_NAME="  Любимые рецепты  ")

    assert settings.mail.sender_name == "Любимые рецепты"


def test_sender_name_of_maximum_length_is_accepted(monkeypatch: pytest.MonkeyPatch) -> None:
    settings = _build(monkeypatch, MAIL__SENDER_NAME="р" * 100)

    assert settings.mail.sender_name == "р" * 100


@pytest.mark.parametrize(
    "name",
    ["   ", "р" * 101, "Bad\nName", "Bad\rName", "Bad\tName", "Zero​Width"],
)
def test_invalid_sender_name_is_rejected(monkeypatch: pytest.MonkeyPatch, name: str) -> None:
    with pytest.raises(ValidationError, match="sender_name"):
        _build(monkeypatch, MAIL__SENDER_NAME=name)


def test_prod_rejects_unencrypted_mail(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(ValidationError, match="MAIL__TLS"):
        _build(monkeypatch, **(PROD_ENV | {"MAIL__TLS": "none"}))


@pytest.mark.parametrize(
    "address",
    [
        "no-reply@example.com",
        "no-reply@EXAMPLE.COM",
        "no-reply@example.net",
        "no-reply@mail.example.org",
        "no-reply@recipes.example",
    ],
)
def test_prod_rejects_reserved_example_sender_domain(
    monkeypatch: pytest.MonkeyPatch, address: str
) -> None:
    with pytest.raises(ValidationError, match="MAIL__SENDER_ADDRESS"):
        _build(monkeypatch, **(PROD_ENV | {"MAIL__SENDER_ADDRESS": address}))


@pytest.mark.parametrize(
    "address",
    [
        "no-reply@myexample.ru",
        "no-reply@notexample.com",
        "no-reply@example-recipes.com",
        "no-reply@example.com.ru",
        "no-reply@example.co",
        "example@recipes.ru",
    ],
)
def test_prod_accepts_sender_domain_that_only_resembles_example(
    monkeypatch: pytest.MonkeyPatch, address: str
) -> None:
    settings = _build(monkeypatch, **(PROD_ENV | {"MAIL__SENDER_ADDRESS": address}))

    assert settings.mail.sender_address == address


def test_env_example_yields_working_local_settings() -> None:
    settings = Settings(_env_file=ENV_EXAMPLE)

    assert settings.app.env == "local"
    assert settings.app.public_base_url == "http://localhost:8000"
    assert settings.mail.tls == "none"
    assert settings.mail.username is None
    assert settings.mail.password is None
