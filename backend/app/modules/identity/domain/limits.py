from dataclasses import dataclass
from datetime import timedelta


@dataclass(frozen=True, slots=True)
class RateLimit:
    limit: int
    window: timedelta


NICKNAME_CHANGE_LIMIT = RateLimit(3, timedelta(days=1))
NICKNAME_CHECK_LIMIT = RateLimit(60, timedelta(minutes=1))
REGISTRATION_EMAIL_LIMIT = RateLimit(5, timedelta(hours=1))
REGISTRATION_IP_LIMIT = RateLimit(20, timedelta(hours=1))
RESEND_CONFIRMATION_EMAIL_LIMIT = RateLimit(5, timedelta(hours=1))
RESEND_CONFIRMATION_IP_LIMIT = RateLimit(20, timedelta(hours=1))
