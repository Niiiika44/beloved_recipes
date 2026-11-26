from collections.abc import Collection
from datetime import timedelta
from types import TracebackType
from typing import Protocol, Self
from uuid import UUID

from app.modules.identity.domain.enums import (
    EmailPurpose,
    IdentityProvider,
    LoginMethod,
    TokenPurpose,
)
from app.modules.identity.domain.limits import RateLimit
from app.modules.identity.service.dto import (
    EmailJobDTO,
    MembershipDTO,
    OidcIdentityDTO,
    OneTimeTokenDTO,
    PasswordCheckDTO,
    PendingLoginDTO,
    ProviderRejectionDTO,
    ReleasedNicknameDTO,
    SessionDTO,
    UserDTO,
)


class SessionStore(Protocol):
    async def create(self, user_id: UUID, credentials_version: int) -> str: ...

    async def resolve(self, token: str) -> SessionDTO | None: ...

    async def revoke(self, token: str) -> None: ...


class UserRepository(Protocol):
    async def get(self, user_id: UUID) -> UserDTO | None: ...

    async def get_for_update(self, user_id: UUID) -> UserDTO | None: ...

    async def get_membership(self, user_id: UUID) -> MembershipDTO | None: ...

    async def create(
        self,
        email: str,
        display_name: str,
        avatar_url: str | None = None,
        email_verified: bool = False,
    ) -> UUID | None: ...

    async def find_by_email(self, email: str) -> UserDTO | None: ...

    async def find_by_identity(
        self, provider: IdentityProvider, subject: str
    ) -> UserDTO | None: ...

    async def get_identity_subject(
        self, user_id: UUID, provider: IdentityProvider
    ) -> str | None: ...

    async def link_identity(
        self, user_id: UUID, provider: IdentityProvider, subject: str
    ) -> None: ...

    async def unlink_identity(self, user_id: UUID, provider: IdentityProvider) -> None: ...

    async def update_profile(
        self, user_id: UUID, email: str, display_name: str, avatar_url: str | None
    ) -> None: ...

    async def mark_email_verified(self, user_id: UUID) -> None: ...

    async def bump_credentials_version(self, user_id: UUID) -> int: ...


class NicknameRepository(Protocol):
    async def lock(self, nicknames: Collection[str]) -> None: ...

    async def get_owner(self, nickname: str) -> UUID | None: ...

    async def get_release(self, nickname: str) -> ReleasedNicknameDTO | None: ...

    async def change(self, user_id: UUID, current: str | None, new: str) -> None: ...

    async def purge_released(self, older_than: timedelta) -> None: ...


class PasswordRepository(Protocol):
    async def set_hash(self, user_id: UUID, password_hash: str) -> None: ...

    async def get_hash(self, user_id: UUID) -> str | None: ...

    async def delete(self, user_id: UUID) -> None: ...


class EmailJobRepository(Protocol):
    async def enqueue(self, purpose: EmailPurpose, user_id: UUID) -> None: ...

    async def claim(self, batch: int, lease: timedelta) -> list[EmailJobDTO]: ...

    async def complete(self, job_id: UUID) -> None: ...

    async def retry(self, job_id: UUID, delay: timedelta, error: str) -> None: ...

    async def fail(self, job_id: UUID, error: str) -> None: ...

    async def purge_failed(self, older_than: timedelta) -> None: ...


class UnitOfWork(Protocol):
    users: UserRepository
    nicknames: NicknameRepository
    passwords: PasswordRepository
    email_jobs: EmailJobRepository

    async def commit(self) -> None: ...

    async def __aenter__(self) -> Self: ...

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None: ...


class RateLimiter(Protocol):
    async def hit(self, key: str, rule: RateLimit) -> int | None: ...


class PasswordHasher(Protocol):
    async def hash_password(self, password: str) -> str: ...

    async def verify(self, password_hash: str, password: str) -> PasswordCheckDTO: ...

    async def verify_dummy(self, password: str) -> None: ...


class BreachedPasswordChecker(Protocol):
    async def is_breached(self, password: str) -> bool | None: ...


class SecurityEvents(Protocol):
    def rate_limited(self, action: str, scope: str) -> None: ...

    def breach_check_unavailable(self) -> None: ...

    def email_confirmed(self, user_id: UUID) -> None: ...

    def login_succeeded(self, user_id: UUID, method: LoginMethod) -> None: ...

    def login_failed(self, user_id: UUID | None, reason: str) -> None: ...

    def logout(self, user_id: UUID | None) -> None: ...

    def password_reset_requested(self, user_id: UUID | None) -> None: ...

    def password_reset_completed(self, user_id: UUID) -> None: ...

    def password_changed(self, user_id: UUID) -> None: ...

    def reset_token_cleanup_failed(self) -> None: ...

    def google_linked(self, user_id: UUID, subject: str) -> None: ...

    def account_relinked(self, user_id: UUID, old_subject: str, new_subject: str) -> None: ...

    def unverified_account_claimed(self, user_id: UUID) -> None: ...

    def google_login_rejected(self, user_id: UUID | None, reason: str) -> None: ...

    def google_disowned(self, user_id: UUID) -> None: ...


class OneTimeTokenStore(Protocol):
    async def issue(
        self, purpose: TokenPurpose, user_id: UUID, credentials_version: int, ttl: timedelta
    ) -> str: ...

    async def consume(self, purpose: TokenPurpose, token: str) -> OneTimeTokenDTO | None: ...

    async def peek(self, purpose: TokenPurpose, token: str) -> OneTimeTokenDTO | None: ...


class Mailer(Protocol):
    async def send(
        self, recipient: str, recipient_name: str, purpose: EmailPurpose, link: str | None
    ) -> None: ...


class OidcProvider(Protocol):
    def authorization_url(self, state: str, nonce: str, code_challenge: str) -> str: ...

    async def exchange_code(
        self, code: str, code_verifier: str
    ) -> OidcIdentityDTO | ProviderRejectionDTO: ...


class LoginStateStore(Protocol):
    async def save(self, state: str, pending: PendingLoginDTO, ttl: timedelta) -> None: ...

    async def pop(self, state: str) -> PendingLoginDTO | None: ...
