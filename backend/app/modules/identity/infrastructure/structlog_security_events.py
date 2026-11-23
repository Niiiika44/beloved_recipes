from uuid import UUID

import structlog


class StructlogSecurityEvents:
    def __init__(self) -> None:
        self._logger = structlog.get_logger("security")

    def rate_limited(self, action: str, scope: str) -> None:
        self._logger.warning("security.rate_limited", action=action, scope=scope)

    def breach_check_unavailable(self) -> None:
        self._logger.warning("security.breach_check_unavailable")

    def email_confirmed(self, user_id: UUID) -> None:
        self._logger.info("security.email_confirmed", user_id=str(user_id))
