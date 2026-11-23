from uuid import UUID

import structlog

from app.modules.identity.domain.enums import LoginMethod


class StructlogSecurityEvents:
    def __init__(self) -> None:
        self._logger = structlog.get_logger("security")

    def rate_limited(self, action: str, scope: str) -> None:
        self._logger.warning("security.rate_limited", action=action, scope=scope)

    def breach_check_unavailable(self) -> None:
        self._logger.warning("security.breach_check_unavailable")

    def email_confirmed(self, user_id: UUID) -> None:
        self._logger.info("security.email_confirmed", user_id=str(user_id))

    def login_succeeded(self, user_id: UUID, method: LoginMethod) -> None:
        self._logger.info("security.login_succeeded", user_id=str(user_id), method=method.value)

    def login_failed(self, reason: str) -> None:
        self._logger.info("security.login_failed", reason=reason)

    def logout(self, user_id: UUID | None) -> None:
        self._logger.info("security.logout", user_id=str(user_id) if user_id else None)
