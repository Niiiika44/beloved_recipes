import unicodedata

from app.modules.identity.domain.exceptions import WeakPasswordError

PASSWORD_MIN_LENGTH = 8
PASSWORD_MAX_LENGTH = 128


def normalize_password(raw: str) -> str:
    """Return the form to hash and to verify against; spaces are part of the password."""
    password = unicodedata.normalize("NFKC", raw)
    if not password.strip():
        raise WeakPasswordError("blank")
    if len(password) < PASSWORD_MIN_LENGTH:
        raise WeakPasswordError("too_short")
    if len(password) > PASSWORD_MAX_LENGTH:
        raise WeakPasswordError("too_long")
    return password
