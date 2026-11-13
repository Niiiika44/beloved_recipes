from app.modules.identity.domain.exceptions import InvalidDisplayNameError
from app.modules.identity.domain.text import ALLOWED_FORMAT_CHARACTERS, has_control_characters

DISPLAY_NAME_MAX_LENGTH = 100


def normalize_display_name(raw: str) -> str:
    display_name = raw.strip()
    if not display_name:
        raise InvalidDisplayNameError("empty")
    if len(display_name) > DISPLAY_NAME_MAX_LENGTH:
        raise InvalidDisplayNameError("too_long")
    if has_control_characters(display_name, allowed=ALLOWED_FORMAT_CHARACTERS):
        raise InvalidDisplayNameError("bad_characters")
    return display_name
