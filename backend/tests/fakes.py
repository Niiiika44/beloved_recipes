import uuid
from collections.abc import Collection, Iterable
from datetime import timedelta
from types import TracebackType
from typing import Self

from app.modules.identity.domain.enums import EmailPurpose, TokenPurpose
from app.modules.identity.domain.limits import RateLimit
from app.modules.identity.service.dto import (
    EmailJobDTO,
    MembershipDTO,
    ReleasedNicknameDTO,
    UserDTO,
)
from app.modules.identity.service.ports import (
    EmailJobRepository,
    NicknameRepository,
    PasswordRepository,
    UserRepository,
)


def make_user(name: str = "Cook", nickname: str | None = None) -> UserDTO:
    return UserDTO(
        id=uuid.uuid7(),
        nickname=nickname,
        email=f"{name.lower()}@example.com",
        display_name=name,
        avatar_url=None,
        email_verified_at=None,
    )


class FakeUsers:
    def __init__(self, uow: FakeUnitOfWork) -> None:
        self._uow = uow

    async def get(self, user_id: uuid.UUID) -> UserDTO | None:
        self._uow.record("get")
        return self._uow.stored.get(user_id)

    async def get_for_update(self, user_id: uuid.UUID) -> UserDTO | None:
        self._uow.record("get_for_update")
        return self._uow.stored.get(user_id)

    async def get_membership(self, user_id: uuid.UUID) -> MembershipDTO | None:
        self._uow.record("get_membership")
        return self._uow.memberships.get(user_id)

    async def create(self, email: str, display_name: str) -> uuid.UUID | None:
        self._uow.record("create")
        if self._uow.find_email(email) is not None:
            return None
        user = UserDTO(
            id=uuid.uuid7(),
            nickname=None,
            email=email,
            display_name=display_name,
            avatar_url=None,
            email_verified_at=None,
        )
        self._uow.stored[user.id] = user
        self._uow.created.append(user)
        return user.id

    async def find_by_email(self, email: str) -> UserDTO | None:
        self._uow.record("find_by_email")
        return self._uow.find_email(email)

    async def mark_email_verified(self, user_id: uuid.UUID) -> None:
        self._uow.record("mark_email_verified")
        self._uow.verified.append(user_id)


class FakeNicknames:
    def __init__(self, uow: FakeUnitOfWork) -> None:
        self._uow = uow

    async def lock(self, nicknames: Collection[str]) -> None:
        self._uow.record("lock")
        self._uow.locked.append(sorted(nicknames))

    async def get_owner(self, nickname: str) -> uuid.UUID | None:
        self._uow.record("get_owner")
        owners = [user.id for user in self._uow.stored.values() if user.nickname == nickname]
        return owners[0] if owners else None

    async def get_release(self, nickname: str) -> ReleasedNicknameDTO | None:
        self._uow.record("get_release")
        return self._uow.releases.get(nickname)

    async def change(self, user_id: uuid.UUID, current: str | None, new: str) -> None:
        self._uow.record("change")
        self._uow.changes.append((user_id, current, new))

    async def purge_released(self, older_than: timedelta) -> None:
        self._uow.record("purge_released")
        self._uow.purged.append(("released_nicknames", older_than))


class FakePasswords:
    def __init__(self, uow: FakeUnitOfWork) -> None:
        self._uow = uow

    async def set_hash(self, user_id: uuid.UUID, password_hash: str) -> None:
        self._uow.record("set_hash")
        self._uow.password_hashes[user_id] = password_hash


class FakeEmailJobs:
    def __init__(self, uow: FakeUnitOfWork) -> None:
        self._uow = uow

    async def enqueue(self, purpose: EmailPurpose, user_id: uuid.UUID) -> None:
        self._uow.record("enqueue")
        self._uow.jobs.append((purpose, user_id))

    async def claim(self, batch: int, lease: timedelta) -> list[EmailJobDTO]:
        self._uow.record("claim")
        self._uow.claims.append((batch, lease))
        taken = self._uow.queued[:batch]
        del self._uow.queued[:batch]
        return taken

    async def complete(self, job_id: uuid.UUID) -> None:
        self._uow.record("complete")
        self._uow.outcomes.append(("complete", job_id, None, None))

    async def retry(self, job_id: uuid.UUID, delay: timedelta, error: str) -> None:
        self._uow.record("retry")
        self._uow.outcomes.append(("retry", job_id, delay, error))

    async def fail(self, job_id: uuid.UUID, error: str) -> None:
        self._uow.record("fail")
        self._uow.outcomes.append(("fail", job_id, None, error))

    async def purge_failed(self, older_than: timedelta) -> None:
        self._uow.record("purge_failed")
        self._uow.purged.append(("email_jobs", older_than))


class FakeUnitOfWork:
    users: UserRepository
    nicknames: NicknameRepository
    passwords: PasswordRepository
    email_jobs: EmailJobRepository

    def __init__(
        self,
        users: Iterable[UserDTO] = (),
        memberships: dict[uuid.UUID, MembershipDTO] | None = None,
        releases: dict[str, ReleasedNicknameDTO] | None = None,
    ) -> None:
        self.stored = {user.id: user for user in users}
        self.memberships = dict(memberships or {})
        self.releases = dict(releases or {})
        self.active = False
        self.commits = 0
        self.calls: list[str] = []
        self.locked: list[list[str]] = []
        self.changes: list[tuple[uuid.UUID, str | None, str]] = []
        self.created: list[UserDTO] = []
        self.password_hashes: dict[uuid.UUID, str] = {}
        self.jobs: list[tuple[EmailPurpose, uuid.UUID]] = []
        self.verified: list[uuid.UUID] = []
        self.purged: list[tuple[str, timedelta]] = []
        self.queued: list[EmailJobDTO] = []
        self.claims: list[tuple[int, timedelta]] = []
        self.outcomes: list[tuple[str, uuid.UUID, timedelta | None, str | None]] = []
        self.users = FakeUsers(self)
        self.nicknames = FakeNicknames(self)
        self.passwords = FakePasswords(self)
        self.email_jobs = FakeEmailJobs(self)

    def find_email(self, email: str) -> UserDTO | None:
        found = [user for user in self.stored.values() if user.email.lower() == email.lower()]
        return found[0] if found else None

    def record(self, call: str) -> None:
        assert self.active, f"{call} used outside the unit of work"
        self.calls.append(call)

    async def commit(self) -> None:
        self.record("commit")
        self.commits += 1

    async def __aenter__(self) -> Self:
        self.active = True
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        self.active = False


class FakeLimiter:
    def __init__(
        self,
        uow: FakeUnitOfWork | None = None,
        retry_after: int | None = None,
        failure: Exception | None = None,
    ) -> None:
        self.uow = uow
        self.retry_after = retry_after
        self.failure = failure
        self.hits: list[tuple[str, RateLimit]] = []
        self.hit_inside_uow: list[bool] = []

    async def hit(self, key: str, rule: RateLimit) -> int | None:
        self.hits.append((key, rule))
        if self.uow is not None:
            self.uow.calls.append("hit")
            self.hit_inside_uow.append(self.uow.active)
        if self.failure is not None:
            raise self.failure
        return self.retry_after


class FakeHasher:
    def __init__(self, uow: FakeUnitOfWork | None = None) -> None:
        self.uow = uow
        self.passwords: list[str] = []

    async def hash_password(self, password: str) -> str:
        self.passwords.append(password)
        if self.uow is not None:
            self.uow.calls.append("hash")
        return f"$argon2id$fake${len(self.passwords)}"


class FakeBreachChecker:
    def __init__(self, answer: bool | None = False, uow: FakeUnitOfWork | None = None) -> None:
        self.answer = answer
        self.uow = uow
        self.passwords: list[str] = []

    async def is_breached(self, password: str) -> bool | None:
        self.passwords.append(password)
        if self.uow is not None:
            self.uow.calls.append("is_breached")
        return self.answer


class FakeEvents:
    def __init__(self) -> None:
        self.recorded: list[tuple[str, ...]] = []

    def rate_limited(self, action: str, scope: str) -> None:
        self.recorded.append(("rate_limited", action, scope))

    def breach_check_unavailable(self) -> None:
        self.recorded.append(("breach_check_unavailable",))

    def email_confirmed(self, user_id: uuid.UUID) -> None:
        self.recorded.append(("email_confirmed", str(user_id)))


class FakeTokens:
    def __init__(self, uow: FakeUnitOfWork | None = None, failure: Exception | None = None) -> None:
        self.uow = uow
        self.failure = failure
        self.issued: list[tuple[TokenPurpose, uuid.UUID, timedelta, str]] = []
        self.live: dict[tuple[TokenPurpose, str], uuid.UUID] = {}

    async def issue(self, purpose: TokenPurpose, user_id: uuid.UUID, ttl: timedelta) -> str:
        if self.uow is not None:
            self.uow.calls.append("issue")
        if self.failure is not None:
            raise self.failure
        token = f"token-{len(self.issued) + 1}"
        self.issued.append((purpose, user_id, ttl, token))
        self.live[(purpose, token)] = user_id
        return token

    async def consume(self, purpose: TokenPurpose, token: str) -> uuid.UUID | None:
        return self.live.pop((purpose, token), None)


class FakeMailer:
    def __init__(
        self, uow: FakeUnitOfWork | None = None, failures: Iterable[Exception] = ()
    ) -> None:
        self.uow = uow
        self.failures = list(failures)
        self.sent: list[tuple[str, str, EmailPurpose, str | None]] = []
        self.sent_inside_uow: list[bool] = []

    async def send(
        self, recipient: str, recipient_name: str, purpose: EmailPurpose, link: str | None
    ) -> None:
        if self.uow is not None:
            self.uow.calls.append("send")
            self.sent_inside_uow.append(self.uow.active)
        if self.failures:
            raise self.failures.pop(0)
        self.sent.append((recipient, recipient_name, purpose, link))
