import hashlib
import hmac


def email_fingerprint(email: str, secret: bytes) -> str:
    return hmac.new(secret, email.lower().encode(), hashlib.sha256).hexdigest()
