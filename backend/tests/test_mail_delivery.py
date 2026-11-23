import uuid
from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest
import structlog
from fakes import FakeMailer, FakeTokens, FakeUnitOfWork, make_user

from app.core.exceptions import DependencyUnavailableError
from app.modules.identity.domain.enums import EmailPurpose, TokenPurpose
from app.modules.identity.service.dto import EmailJobDTO, UserDTO
from app.modules.identity.service.exceptions import (
    MailDeliveryPermanentError,
    MailDeliveryTemporaryError,
)
from app.modules.identity.service.mail_delivery import MailDeliveryService

BASE_URL = "https://recipes.example"
LEASE = timedelta(minutes=5)
VERIFIED_AT = datetime(2026, 11, 1, tzinfo=UTC)


class World:
    def __init__(self, *users: UserDTO, failures: tuple[Exception, ...] = ()) -> None:
        self.uow = FakeUnitOfWork(users)
        self.tokens = FakeTokens(self.uow)
        self.mailer = FakeMailer(self.uow, failures)
        self.service = MailDeliveryService(
            uow=self.uow,
            tokens=self.tokens,
            mailer=self.mailer,
            public_base_url=BASE_URL,
            batch=7,
            lease=LEASE,
        )

    def queue(
        self, user: UserDTO, purpose: EmailPurpose = EmailPurpose.EMAIL_CONFIRM, attempts: int = 1
    ) -> EmailJobDTO:
        job = EmailJobDTO(id=uuid.uuid7(), user_id=user.id, purpose=purpose, attempts=attempts)
        self.uow.queued.append(job)
        return job


def _anna(verified: bool = False) -> UserDTO:
    return replace(
        make_user("Anna"),
        email="anna@example.org",
        email_verified_at=VERIFIED_AT if verified else None,
    )


async def test_confirmation_is_sent_with_a_fresh_token_link() -> None:
    anna = _anna()
    world = World(anna)
    job = world.queue(anna)

    taken = await world.service.deliver_batch()

    assert taken == 1
    assert world.tokens.issued == [
        (TokenPurpose.EMAIL_CONFIRM, anna.id, timedelta(hours=24), "token-1")
    ]
    assert world.mailer.sent == [
        (
            "anna@example.org",
            anna.display_name,
            EmailPurpose.EMAIL_CONFIRM,
            f"{BASE_URL}/auth/confirm#token=token-1",
        )
    ]
    assert world.uow.outcomes == [("complete", job.id, None, None)]


async def test_already_registered_links_to_password_reset_without_token() -> None:
    anna = _anna(verified=True)
    world = World(anna)
    world.queue(anna, EmailPurpose.ALREADY_REGISTERED)

    await world.service.deliver_batch()

    assert world.tokens.issued == []
    assert world.mailer.sent[0][3] == f"{BASE_URL}/auth/forgot"


async def test_batch_size_and_lease_come_from_the_service() -> None:
    world = World()

    await world.service.deliver_batch()

    assert world.uow.claims == [(7, LEASE)]


async def test_empty_queue_reports_nothing_taken() -> None:
    world = World()

    assert await world.service.deliver_batch() == 0
    assert world.mailer.sent == []


async def test_letter_leaves_outside_any_transaction_after_short_ones() -> None:
    anna = _anna()
    world = World(anna)
    world.queue(anna)

    await world.service.deliver_batch()

    assert world.uow.calls == ["claim", "commit", "get", "issue", "send", "complete", "commit"]
    assert world.mailer.sent_inside_uow == [False]


async def test_missing_user_is_completed_without_letter() -> None:
    ghost = _anna()
    world = World()
    job = world.queue(ghost)

    await world.service.deliver_batch()

    assert world.mailer.sent == []
    assert world.tokens.issued == []
    assert world.uow.outcomes == [("complete", job.id, None, None)]


async def test_confirmation_for_verified_user_is_skipped() -> None:
    anna = _anna(verified=True)
    world = World(anna)
    job = world.queue(anna)

    await world.service.deliver_batch()

    assert world.mailer.sent == []
    assert world.tokens.issued == []
    assert world.uow.outcomes == [("complete", job.id, None, None)]


async def test_permanent_failure_fails_the_job_at_once() -> None:
    anna = _anna()
    world = World(anna, failures=(MailDeliveryPermanentError("recipient refused"),))
    job = world.queue(anna)

    await world.service.deliver_batch()

    assert world.uow.outcomes == [("fail", job.id, None, "permanent: recipient refused")]


@pytest.mark.parametrize(
    ("attempts", "delay"),
    [(1, timedelta(seconds=30)), (3, timedelta(minutes=2)), (7, timedelta(minutes=32))],
)
async def test_temporary_failure_is_retried_later(attempts: int, delay: timedelta) -> None:
    anna = _anna()
    world = World(anna, failures=(MailDeliveryTemporaryError("SMTPConnectError"),))
    job = world.queue(anna, attempts=attempts)

    await world.service.deliver_batch()

    assert world.uow.outcomes == [("retry", job.id, delay, "temporary: SMTPConnectError")]


async def test_eighth_temporary_failure_gives_up() -> None:
    anna = _anna()
    world = World(anna, failures=(MailDeliveryTemporaryError("SMTPConnectError"),))
    job = world.queue(anna, attempts=8)

    await world.service.deliver_batch()

    assert world.uow.outcomes == [("fail", job.id, None, "temporary: SMTPConnectError")]


async def test_job_over_the_attempt_limit_fails_before_sending() -> None:
    anna = _anna()
    world = World(anna)
    job = world.queue(anna, attempts=9)

    await world.service.deliver_batch()

    assert world.mailer.sent == []
    assert world.uow.outcomes == [("fail", job.id, None, "attempts_exhausted")]


async def test_purpose_without_a_letter_fails() -> None:
    anna = _anna()
    world = World(anna)
    job = world.queue(anna, EmailPurpose.PASSWORD_RESET)

    await world.service.deliver_batch()

    assert world.mailer.sent == []
    assert world.uow.outcomes == [("fail", job.id, None, "unsupported_purpose")]


async def test_token_store_outage_is_retried() -> None:
    anna = _anna()
    world = World(anna)
    world.tokens.failure = DependencyUnavailableError("Token store is unavailable")
    job = world.queue(anna)

    await world.service.deliver_batch()

    assert world.mailer.sent == []
    assert world.uow.outcomes == [
        ("retry", job.id, timedelta(seconds=30), "temporary: Token store is unavailable")
    ]


async def test_unexpected_error_is_logged_and_retried() -> None:
    anna = _anna()
    world = World(anna, failures=(RuntimeError("template broken"),))
    job = world.queue(anna)

    with structlog.testing.capture_logs() as records:
        await world.service.deliver_batch()

    assert world.uow.outcomes == [("retry", job.id, timedelta(seconds=30), "unexpected")]
    assert any(record["event"] == "mail.unexpected_error" for record in records)


async def test_one_failing_letter_does_not_stop_the_batch() -> None:
    anna = _anna()
    boris = replace(make_user("Boris"), email="boris@example.org")
    world = World(anna, boris, failures=(MailDeliveryTemporaryError("SMTPConnectError"),))
    first = world.queue(anna)
    second = world.queue(boris)

    assert await world.service.deliver_batch() == 2

    assert [outcome[:2] for outcome in world.uow.outcomes] == [
        ("retry", first.id),
        ("complete", second.id),
    ]
    assert [letter[0] for letter in world.mailer.sent] == ["boris@example.org"]


async def test_logs_name_the_job_but_never_the_address() -> None:
    anna = _anna()
    world = World(anna, failures=(MailDeliveryTemporaryError("SMTPConnectError"),))
    world.queue(anna)
    world.queue(anna, EmailPurpose.ALREADY_REGISTERED)

    with structlog.testing.capture_logs() as records:
        await world.service.deliver_batch()

    events = [record["event"] for record in records]
    assert events == ["mail.retry", "mail.sent"]
    assert all({"job_id", "user_id", "purpose", "attempts"} <= set(record) for record in records)
    assert "anna@example.org" not in repr(records)
    assert "token-" not in repr(records)
