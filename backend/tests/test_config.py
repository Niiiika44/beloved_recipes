import os
from pathlib import Path
from urllib.parse import unquote, urlsplit

import pytest
from pydantic import ValidationError

from app.core.config import Settings, get_settings

SECTIONS = ("APP", "DB", "REDIS", "SECURITY")

REQUIRED_ENV = {
    "DB__USER": "recipes",
    "DB__PASSWORD": "db-secret",
    "DB__NAME": "recipes",
    "REDIS__PASSWORD": "redis-secret",
    "SECURITY__SECRET_KEY": "s" * 32,
}

TRICKY_PASSWORD = "p@ss/wo rd#1:2?3"


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
    assert reported == {"db", "redis", "security"}


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
        _build(monkeypatch, APP__ENV="prod", SECURITY__SECRET_KEY="short")


def test_prod_accepts_long_secret_key(monkeypatch: pytest.MonkeyPatch) -> None:
    settings = _build(monkeypatch, APP__ENV="prod", SECURITY__SECRET_KEY="k" * 32)

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
