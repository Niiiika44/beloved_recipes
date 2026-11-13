from app.modules.identity.domain.text import has_control_characters

NEXT_MAX_LENGTH = 2048
DEFAULT_NEXT = "/"


def safe_next(raw: str | None) -> str:
    """Return a same-site path to go to after login, or "/" when raw is not one."""
    if not raw or len(raw) > NEXT_MAX_LENGTH:
        return DEFAULT_NEXT
    if not raw.startswith("/") or raw.startswith("//") or "\\" in raw:
        return DEFAULT_NEXT
    if has_control_characters(raw):
        return DEFAULT_NEXT
    return raw
