from typing import Literal


class MailDeliveryTemporaryError(Exception):
    pass


class MailDeliveryPermanentError(Exception):
    pass


GoogleRejectionCode = Literal[
    "state",
    "provider",
    "nonce",
    "email_unverified",
    "email_conflict",
    "rate_limited",
]


class GoogleRejectedError(Exception):
    def __init__(self, code: GoogleRejectionCode):
        super().__init__(code)
        self.code = code
