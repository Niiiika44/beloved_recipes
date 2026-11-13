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


class IdentityProvider(StrEnum):
    """Methods of identity verification"""

    GOOGLE = "google"


class EmailPurpose(StrEnum):
    """Purpose of sending email letter"""

    EMAIL_CONFIRM = "email_confirm"
    PASSWORD_RESET = "password_reset"  # noqa: S105
    ALREADY_REGISTERED = "already_registered"


class EmailJobStatus(StrEnum):
    """Status of email sending job"""

    PENDING = "pending"
    FAILED = "failed"


class TokenPurpose(StrEnum):
    """What a one-time token from an email link is allowed to do"""

    EMAIL_CONFIRM = "email_confirm"
    PASSWORD_RESET = "password_reset"  # noqa: S105


class LoginMethod(StrEnum):
    """How the user proved who they are"""

    GOOGLE = "google"
    PASSWORD = "password"  # noqa: S105
