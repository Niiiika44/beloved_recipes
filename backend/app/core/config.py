import unicodedata
from functools import lru_cache
from pathlib import Path
from typing import Literal, Self
from urllib.parse import quote

from pydantic import (
    BaseModel,
    ConfigDict,
    EmailStr,
    Field,
    HttpUrl,
    SecretStr,
    field_validator,
    model_validator,
)
from pydantic_settings import BaseSettings, SettingsConfigDict

ENV_FILE = Path(__file__).resolve().parents[3] / "infra" / ".env"

MIN_PROD_SECRET_KEY_LENGTH = 32

RESERVED_EXAMPLE_DOMAINS = ("example.com", "example.net", "example.org", "example")


def _is_reserved_example_domain(address: str) -> bool:
    domain = address.rpartition("@")[2]
    return any(
        domain == reserved or domain.endswith(f".{reserved}")
        for reserved in RESERVED_EXAMPLE_DOMAINS
    )


class _Section(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, validate_default=True)


class AppSection(_Section):
    env: Literal["local", "ci", "prod"] = "local"
    name: str = "beloved_recipes"
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"
    public_base_url: str = "http://localhost:8000"

    @field_validator("public_base_url")
    @classmethod
    def _origin_only(cls, value: str) -> str:
        url = HttpUrl(value)
        if url.path not in (None, "/") or url.query or url.fragment or url.username or url.password:
            raise ValueError("APP__PUBLIC_BASE_URL must be an origin: scheme://host[:port]")
        return str(url).rstrip("/")

    @property
    def is_prod(self) -> bool:
        return self.env == "prod"


class SessionSection(_Section):
    cookie_name: str = "session"
    cookie_secure: bool = False
    idle_ttl_seconds: int = Field(1_209_600, gt=0)
    absolute_ttl_seconds: int = Field(2_592_000, gt=0)
    operation_timeout_seconds: float = Field(1.0, gt=0)

    @model_validator(mode="after")
    def _validate_consistency(self) -> Self:
        if self.absolute_ttl_seconds < self.idle_ttl_seconds:
            raise ValueError(
                "SESSION__ABSOLUTE_TTL_SECONDS should be greater than "
                "or equal to SESSION__IDLE_TTL_SECONDS"
            )
        if (
            self.cookie_name.startswith("__Host-") or self.cookie_name.startswith("__Secure-")
        ) and not self.cookie_secure:
            raise ValueError(
                "SESSION__COOKIE_NAME with prefixes __Host- or __Secure- should be secure"
            )
        return self


class GoogleSection(_Section):
    client_id: str
    client_secret: SecretStr


class MailSection(_Section):
    host: str = "127.0.0.1"
    port: int = 1025
    tls: Literal["tls", "none"] = "none"
    username: str | None = Field(None, min_length=1)
    password: SecretStr | None = Field(None, min_length=1)
    sender_name: str = Field("Beloved Recipes", min_length=1, max_length=100)
    sender_address: EmailStr = "no-reply@example.com"

    @field_validator("sender_name", mode="before")
    @classmethod
    def _validate_sender_name(cls, value: str) -> str:
        sender_name = value.strip()
        if any(unicodedata.category(c).startswith("C") for c in value):
            raise ValueError("MAIL__SENDER_NAME should not contain control_chars")
        return sender_name

    @model_validator(mode="after")
    def _validate_consistency(self) -> Self:
        if self.password is not None and self.username is None:
            raise ValueError("MAIL__USERNAME should not be empty")
        if self.username is not None and self.password is None:
            raise ValueError("MAIL__PASSWORD should not be empty")
        return self


class DatabaseSection(_Section):
    host: str = "127.0.0.1"
    port: int = 5432
    user: str
    password: SecretStr
    name: str

    pool_size: int = 5
    max_overflow: int = 10
    pool_recycle_seconds: int = 1800
    statement_timeout_ms: int = 5_000
    idle_in_transaction_timeout_ms: int = 10_000

    @property
    def dsn(self) -> str:
        user = quote(self.user, safe="")
        password = quote(self.password.get_secret_value(), safe="")
        return f"postgresql+asyncpg://{user}:{password}@{self.host}:{self.port}/{self.name}"


class RedisSection(_Section):
    host: str = "127.0.0.1"
    port: int = 6379
    password: SecretStr
    db: int = 0
    socket_timeout_seconds: int = 2
    socket_connect_timeout_seconds: int = 2
    max_connections: int = 10
    health_check_interval: int = 10

    @property
    def dsn(self) -> str:
        password = quote(self.password.get_secret_value(), safe="")
        return f"redis://:{password}@{self.host}:{self.port}/{self.db}"


class SecuritySection(_Section):
    secret_key: SecretStr


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=ENV_FILE,
        env_file_encoding="utf-8",
        env_nested_delimiter="__",
        extra="ignore",
        case_sensitive=False,
        frozen=True,
        env_ignore_empty=True,
    )

    app: AppSection = Field(default_factory=AppSection)
    db: DatabaseSection
    session: SessionSection = Field(default_factory=SessionSection)
    redis: RedisSection
    security: SecuritySection
    google: GoogleSection
    mail: MailSection = Field(default_factory=MailSection)

    @model_validator(mode="after")
    def _validate_prod_requirements(self) -> Self:
        if not self.app.is_prod:
            return self

        if not self.app.public_base_url.startswith("https://"):
            raise ValueError("APP__PUBLIC_BASE_URL should start with `https://`")
        secret_key = self.security.secret_key.get_secret_value()
        if len(secret_key) < MIN_PROD_SECRET_KEY_LENGTH:
            raise ValueError(
                f"SECURITY__SECRET_KEY is shorter than {MIN_PROD_SECRET_KEY_LENGTH} symbols"
            )
        if not self.session.cookie_secure:
            raise ValueError("SESSION__COOKIE_SECURE should be true")
        if not self.session.cookie_name.startswith("__Host-"):
            raise ValueError("SESSION__COOKIE_NAME should start with __Host- prefix")
        if self.mail.tls == "none":
            raise ValueError("MAIL__TLS should be tls")
        if _is_reserved_example_domain(self.mail.sender_address):
            raise ValueError("MAIL__SENDER_ADDRESS should not use a reserved example domain")
        return self


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
