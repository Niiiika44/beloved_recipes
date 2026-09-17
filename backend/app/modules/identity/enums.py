from enum import StrEnum


class WorkspaceTheme(StrEnum):
    """Available themes of the workspace"""

    DARK = "dark"
    LIGHT = "light"
    PINK = "pink"


class WorkspaceRole(StrEnum):
    """Roles of user's at the workspace"""

    OWNER = "owner"
    MEMBER = "member"
