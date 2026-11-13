import unicodedata

ALLOWED_FORMAT_CHARACTERS = frozenset({"‍"})


def has_control_characters(value: str, allowed: frozenset[str] = frozenset()) -> bool:
    return any(
        unicodedata.category(character).startswith("C") and character not in allowed
        for character in value
    )
