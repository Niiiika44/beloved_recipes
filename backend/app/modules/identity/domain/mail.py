from datetime import timedelta

EMAIL_CONFIRM_TOKEN_TTL = timedelta(hours=24)
PASSWORD_RESET_TOKEN_TTL = timedelta(hours=1)
MAIL_MAX_ATTEMPTS = 8
MAIL_RETRY_BASE = timedelta(seconds=30)
MAIL_RETRY_MAX = timedelta(hours=1)
FAILED_MAIL_RETENTION = timedelta(days=30)
GOOGLE_NOT_ME_TOKEN_TTL = timedelta(days=7)


def retry_delay(attempts: int) -> timedelta:
    return min(MAIL_RETRY_BASE * (1 << (attempts - 1)), MAIL_RETRY_MAX)
