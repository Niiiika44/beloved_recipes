from datetime import timedelta
from typing import Literal

LOGIN_STATE_TTL = timedelta(minutes=10)

ProviderRejectionReason = Literal[
    "invalid_grant",
    "unknown_key",
    "bad_signature",
    "wrong_audience",
    "wrong_issuer",
    "expired",
    "missing_claim",
    "invalid_token",
]
