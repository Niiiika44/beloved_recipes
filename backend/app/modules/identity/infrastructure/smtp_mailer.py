import asyncio
import ssl
from email.headerregistry import Address
from email.message import EmailMessage
from pathlib import Path

import aiosmtplib

from app.core.config import MailSection
from app.modules.identity.domain.enums import EmailPurpose
from app.modules.identity.service.exceptions import (
    MailDeliveryPermanentError,
    MailDeliveryTemporaryError,
)

SMTP_TIMEOUT_SECONDS = 10.0
TEMPLATES = Path(__file__).parent / "mail_templates"


def _render(purpose: EmailPurpose, name: str, link: str | None) -> tuple[str, str]:
    text = (TEMPLATES / f"{purpose.value}.txt").read_text(encoding="utf-8")
    subject, _, body = text.partition("\n\n")
    return subject.strip(), body.format(name=name, link=link or "")


class SmtpMailer:
    def __init__(
        self,
        settings: MailSection,
        tls_context: ssl.SSLContext | None = None,
        timeout_seconds: float = SMTP_TIMEOUT_SECONDS,
    ):
        self._settings = settings
        self._tls_context = tls_context
        self._timeout_seconds = timeout_seconds

    def _message(
        self, recipient: str, recipient_name: str, purpose: EmailPurpose, link: str | None
    ) -> EmailMessage:
        subject, body = _render(purpose, recipient_name, link)
        message = EmailMessage()
        message["From"] = Address(
            display_name=self._settings.sender_name, addr_spec=self._settings.sender_address
        )
        message["To"] = Address(display_name=recipient_name, addr_spec=recipient)
        message["Subject"] = subject
        message.set_content(body)
        return message

    async def send(
        self, recipient: str, recipient_name: str, purpose: EmailPurpose, link: str | None
    ) -> None:
        message = self._message(
            recipient=recipient, recipient_name=recipient_name, purpose=purpose, link=link
        )
        use_tls = self._settings.tls == "tls"
        tls_context = (self._tls_context or ssl.create_default_context()) if use_tls else None
        password = self._settings.password
        try:
            async with asyncio.timeout(self._timeout_seconds):
                await aiosmtplib.send(
                    message,
                    hostname=self._settings.host,
                    port=self._settings.port,
                    username=self._settings.username,
                    password=password.get_secret_value() if password is not None else None,
                    use_tls=use_tls,
                    start_tls=False,
                    tls_context=tls_context,
                    timeout=self._timeout_seconds,
                )
        except aiosmtplib.SMTPRecipientsRefused as exc:
            if all(refusal.code >= 500 for refusal in exc.recipients):
                raise MailDeliveryPermanentError("recipient refused") from exc
            raise MailDeliveryTemporaryError("recipient deferred") from exc
        except (aiosmtplib.SMTPAuthenticationError, aiosmtplib.SMTPSenderRefused) as exc:
            raise MailDeliveryTemporaryError(f"our settings refused: {exc.code}") from exc
        except aiosmtplib.SMTPResponseException as exc:
            if 400 <= exc.code < 500:
                raise MailDeliveryTemporaryError(f"server replied {exc.code}") from exc
            raise MailDeliveryPermanentError(f"server replied {exc.code}") from exc
        except (aiosmtplib.SMTPException, OSError) as exc:
            raise MailDeliveryTemporaryError(type(exc).__name__) from exc
