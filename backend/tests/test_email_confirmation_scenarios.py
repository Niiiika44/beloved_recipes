import uuid
from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest
from fakes import FakeEvents, FakeLimiter, FakeTokens, FakeUnitOfWork, make_user

from app.core.exceptions import DependencyUnavailableError, RateLimitedError
from app.modules.identity.domain.emails import email_fingerprint
from app.modules.identity.domain.enums import EmailPurpose, TokenPurpose
from app.modules.identity.domain.exceptions import InvalidTokenError
from app.modules.identity.domain.limits import (
    RESEND_CONFIRMATION_EMAIL_LIMIT,
    RESEND_CONFIRMATION_IP_LIMIT,
)
from app.modules.identity.domain.mail import FAILED_MAIL_RETENTION
from app.modules.identity.domain.nicknames import NICKNAME_QUARANTINE
from app.modules.identity.service.dto import ResendConfirmationDTO, UserDTO
from app.modules.identity.service.email_confirmation import confirm_email, resend_confirmation
from app.modules.identity.service.maintenance import purge_expired

SECRET = b"resend-secret"
DAY = timedelta(hours=24)
REQUEST = ResendConfirmationDTO(email="Anna@Example.org", client_ip="203.0.113.7")
IP_KEY = "resend_confirmation_ip:203.0.113.7"
EMAIL_KEY = "resend_confirmation_email:" + email_fingerprint("anna@example.org", SECRET)


def _anna(verified: bool = False) -> UserDTO:
    return replace(
        make_user("Anna"),
        email="anna@example.org",
        email_verified_at=datetime(2026, 11, 1, tzinfo=UTC) if verified else None,
    )


async def _issued(tokens: FakeTokens, user_id: uuid.UUID, purpose: TokenPurpose) -> str:
    return await tokens.issue(purpose, user_id, DAY)


async def test_confirmation_marks_the_email_verified() -> None:
    anna = _anna()
    uow = FakeUnitOfWork([anna])
    tokens = FakeTokens()
    events = FakeEvents()
    token = await _issued(tokens, anna.id, TokenPurpose.EMAIL_CONFIRM)

    await confirm_email(token, tokens, uow, events)

    assert uow.verified == [anna.id]
    assert uow.commits == 1
    assert events.recorded == [("email_confirmed", str(anna.id))]


@pytest.mark.parametrize("token", ["unknown", ""], ids=["unknown", "empty"])
async def test_unknown_token_is_rejected_and_changes_nothing(token: str) -> None:
    uow = FakeUnitOfWork([_anna()])
    events = FakeEvents()

    with pytest.raises(InvalidTokenError):
        await confirm_email(token, FakeTokens(), uow, events)

    assert uow.calls == []
    assert events.recorded == []


async def test_token_of_another_purpose_is_rejected() -> None:
    anna = _anna()
    tokens = FakeTokens()
    token = await _issued(tokens, anna.id, TokenPurpose.PASSWORD_RESET)

    with pytest.raises(InvalidTokenError):
        await confirm_email(token, tokens, FakeUnitOfWork([anna]), FakeEvents())


async def test_used_token_is_rejected_the_second_time() -> None:
    anna = _anna()
    uow = FakeUnitOfWork([anna])
    tokens = FakeTokens()
    token = await _issued(tokens, anna.id, TokenPurpose.EMAIL_CONFIRM)
    await confirm_email(token, tokens, uow, FakeEvents())

    with pytest.raises(InvalidTokenError):
        await confirm_email(token, tokens, uow, FakeEvents())

    assert uow.verified == [anna.id]


def _resend_world(
    *users: UserDTO, retry_after: int | None = None, failure: Exception | None = None
) -> tuple[FakeUnitOfWork, FakeLimiter, FakeEvents]:
    uow = FakeUnitOfWork(users)
    return uow, FakeLimiter(uow, retry_after=retry_after, failure=failure), FakeEvents()


async def test_resend_queues_confirmation_for_unverified_user() -> None:
    anna = _anna()
    uow, limiter, events = _resend_world(anna)

    await resend_confirmation(REQUEST, uow, limiter, SECRET, events)

    assert uow.jobs == [(EmailPurpose.EMAIL_CONFIRM, anna.id)]
    assert uow.commits == 1


@pytest.mark.parametrize(
    ("users", "email"),
    [((_anna(verified=True),), "anna@example.org"), ((), "nobody@example.org")],
    ids=["verified", "unknown"],
)
async def test_resend_queues_nothing_for_verified_or_unknown(
    users: tuple[UserDTO, ...], email: str
) -> None:
    uow, limiter, events = _resend_world(*users)

    await resend_confirmation(replace(REQUEST, email=email), uow, limiter, SECRET, events)

    assert uow.jobs == []
    assert uow.commits == 0


async def test_resend_counts_ip_then_email_fingerprint() -> None:
    uow, limiter, events = _resend_world(_anna())

    await resend_confirmation(REQUEST, uow, limiter, SECRET, events)

    assert limiter.hits == [
        (IP_KEY, RESEND_CONFIRMATION_IP_LIMIT),
        (EMAIL_KEY, RESEND_CONFIRMATION_EMAIL_LIMIT),
    ]
    assert all("anna" not in key.lower() for key, _ in limiter.hits)


async def test_resend_without_client_address_shares_one_counter() -> None:
    uow, limiter, events = _resend_world()

    await resend_confirmation(replace(REQUEST, client_ip=None), uow, limiter, SECRET, events)

    assert limiter.hits[0][0] == "resend_confirmation_ip:unknown"


async def test_resend_counters_are_apart_from_registration() -> None:
    uow, limiter, events = _resend_world()

    await resend_confirmation(REQUEST, uow, limiter, SECRET, events)

    assert all(key.startswith("resend_confirmation_") for key, _ in limiter.hits)


async def test_resend_over_the_ip_limit_stops_before_the_email_counter() -> None:
    uow, limiter, events = _resend_world(_anna(), retry_after=1200)

    with pytest.raises(RateLimitedError) as caught:
        await resend_confirmation(REQUEST, uow, limiter, SECRET, events)

    assert caught.value.retry_after_seconds == 1200
    assert limiter.hits == [(IP_KEY, RESEND_CONFIRMATION_IP_LIMIT)]
    assert events.recorded == [("rate_limited", "resend_confirmation", "ip")]
    assert uow.jobs == []


async def test_resend_over_the_email_limit_is_reported_as_email() -> None:
    anna = _anna()
    uow = FakeUnitOfWork([anna])
    events = FakeEvents()

    class EmailLimited(FakeLimiter):
        async def hit(self, key: str, rule: object) -> int | None:
            self.hits.append((key, RESEND_CONFIRMATION_EMAIL_LIMIT))
            return 900 if key == EMAIL_KEY else None

    with pytest.raises(RateLimitedError):
        await resend_confirmation(REQUEST, uow, EmailLimited(), SECRET, events)

    assert events.recorded == [("rate_limited", "resend_confirmation", "email")]
    assert uow.jobs == []


async def test_resend_limiter_outage_is_reported() -> None:
    outage = DependencyUnavailableError("Rate limiter is unavailable")
    uow, limiter, events = _resend_world(_anna(), failure=outage)

    with pytest.raises(DependencyUnavailableError) as caught:
        await resend_confirmation(REQUEST, uow, limiter, SECRET, events)

    assert caught.value is outage


async def test_purge_expired_cleans_both_tables_in_one_transaction() -> None:
    uow = FakeUnitOfWork()

    await purge_expired(uow)

    assert uow.purged == [
        ("email_jobs", FAILED_MAIL_RETENTION),
        ("released_nicknames", NICKNAME_QUARANTINE),
    ]
    assert uow.calls == ["purge_failed", "purge_released", "commit"]
