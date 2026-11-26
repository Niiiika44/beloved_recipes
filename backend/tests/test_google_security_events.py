import uuid

import pytest
import structlog

from app.modules.identity.infrastructure.structlog_security_events import StructlogSecurityEvents
from app.modules.identity.service.ports import SecurityEvents


def test_satisfies_the_port() -> None:
    events: SecurityEvents = StructlogSecurityEvents()

    assert isinstance(events, StructlogSecurityEvents)


def test_google_linked_names_the_user_and_the_subject() -> None:
    user_id = uuid.uuid7()

    with structlog.testing.capture_logs() as records:
        StructlogSecurityEvents().google_linked(user_id, "sub-1")

    assert records == [
        {
            "event": "security.google_linked",
            "user_id": str(user_id),
            "subject": "sub-1",
            "log_level": "info",
        }
    ]


def test_account_relinked_names_both_subjects() -> None:
    user_id = uuid.uuid7()

    with structlog.testing.capture_logs() as records:
        StructlogSecurityEvents().account_relinked(user_id, "sub-old", "sub-new")

    assert records == [
        {
            "event": "security.account_relinked",
            "user_id": str(user_id),
            "old_subject": "sub-old",
            "new_subject": "sub-new",
            "log_level": "info",
        }
    ]


def test_unverified_account_claimed_names_the_user() -> None:
    user_id = uuid.uuid7()

    with structlog.testing.capture_logs() as records:
        StructlogSecurityEvents().unverified_account_claimed(user_id)

    assert records == [
        {
            "event": "security.unverified_account_claimed",
            "user_id": str(user_id),
            "log_level": "info",
        }
    ]


def test_google_disowned_names_the_user() -> None:
    user_id = uuid.uuid7()

    with structlog.testing.capture_logs() as records:
        StructlogSecurityEvents().google_disowned(user_id)

    assert records == [
        {"event": "security.google_disowned", "user_id": str(user_id), "log_level": "info"}
    ]


@pytest.mark.parametrize("reason", ["state", "nonce", "email_unverified", "rate_limited"])
def test_our_own_rejection_is_info(reason: str) -> None:
    with structlog.testing.capture_logs() as records:
        StructlogSecurityEvents().google_login_rejected(None, reason)

    assert records == [
        {
            "event": "security.google_login_rejected",
            "user_id": None,
            "reason": reason,
            "log_level": "info",
        }
    ]


@pytest.mark.parametrize("reason", ["provider:bad_signature", "provider:invalid_grant"])
def test_rejection_by_the_provider_is_a_warning(reason: str) -> None:
    with structlog.testing.capture_logs() as records:
        StructlogSecurityEvents().google_login_rejected(None, reason)

    assert [(record["log_level"], record["reason"]) for record in records] == [("warning", reason)]


def test_rejection_of_a_known_user_names_them() -> None:
    user_id = uuid.uuid7()

    with structlog.testing.capture_logs() as records:
        StructlogSecurityEvents().google_login_rejected(user_id, "email_conflict")

    assert records == [
        {
            "event": "security.google_login_rejected",
            "user_id": str(user_id),
            "reason": "email_conflict",
            "log_level": "info",
        }
    ]
