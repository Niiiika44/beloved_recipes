import asyncio
import json
import shutil
import ssl
import subprocess
import time
import urllib.request
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from smtp_stub import StubSmtp
from testcontainers.core.container import DockerContainer
from testcontainers.core.wait_strategies import HttpWaitStrategy

from app.core.config import MailSection
from app.modules.identity.domain.enums import EmailPurpose
from app.modules.identity.infrastructure.smtp_mailer import SMTP_TIMEOUT_SECONDS, SmtpMailer
from app.modules.identity.service.exceptions import (
    MailDeliveryPermanentError,
    MailDeliveryTemporaryError,
)
from app.modules.identity.service.ports import Mailer

MAILPIT_IMAGE = (
    "axllent/mailpit:v1.33.1"
    "@sha256:aef2aacc11f075ec0fb6874275ee4a421e688e11a96ebb296134d1735c7761ce"
)
SMTP_USER = "mailer"
SMTP_PASSWORD = "mailer-secret"
CONFIRM_LINK = "http://localhost:8000/auth/confirm#token=abc"


async def _serve(stub: StubSmtp) -> tuple[asyncio.Server, int]:
    server = await asyncio.start_server(stub.handle, "127.0.0.1", 0)
    return server, server.sockets[0].getsockname()[1]


async def _send_through(
    stub: StubSmtp, purpose: EmailPurpose = EmailPurpose.EMAIL_CONFIRM, **settings: Any
) -> None:
    timeout_seconds = settings.pop("timeout_seconds", SMTP_TIMEOUT_SECONDS)
    server, port = await _serve(stub)
    try:
        mailer = SmtpMailer(
            MailSection(host="127.0.0.1", port=port, **settings),
            timeout_seconds=timeout_seconds,
        )
        await mailer.send("anna@example.org", "Анна Иванова", purpose, CONFIRM_LINK)
    finally:
        server.close()
        await server.wait_closed()


def test_satisfies_the_port() -> None:
    mailer: Mailer = SmtpMailer(MailSection())

    assert isinstance(mailer, SmtpMailer)


def test_timeout_defaults_to_ten_seconds() -> None:
    assert SMTP_TIMEOUT_SECONDS == 10.0


async def test_confirmation_letter_carries_names_subject_and_link() -> None:
    stub = StubSmtp()

    await _send_through(stub, sender_name="Beloved Recipes", sender_address="no-reply@recipes.ru")

    [message] = stub.messages
    assert message["From"] == "Beloved Recipes <no-reply@recipes.ru>"
    assert message["To"] == "Анна Иванова <anna@example.org>"
    assert message["Subject"] == "Подтвердите адрес почты"
    body = message.get_content()
    assert "Здравствуйте, Анна Иванова!" in body
    assert CONFIRM_LINK in body
    assert "не нажимайте" in body


async def test_already_registered_letter_has_its_own_text() -> None:
    stub = StubSmtp()

    await _send_through(stub, purpose=EmailPurpose.ALREADY_REGISTERED)

    [message] = stub.messages
    assert message["Subject"] == "Вы уже зарегистрированы"
    assert CONFIRM_LINK in message.get_content()


@pytest.mark.parametrize("purpose", [EmailPurpose.EMAIL_CONFIRM, EmailPurpose.ALREADY_REGISTERED])
def test_every_template_has_subject_and_placeholders(purpose: EmailPurpose) -> None:
    template = Path(__file__).resolve().parents[1] / (
        f"app/modules/identity/infrastructure/mail_templates/{purpose.value}.txt"
    )
    subject, separator, body = template.read_text(encoding="utf-8").partition("\n\n")

    assert subject.strip()
    assert "\n" not in subject.strip()
    assert separator
    assert "{name}" in body
    assert "{link}" in body


async def test_plain_mode_never_upgrades_to_starttls() -> None:
    stub = StubSmtp()

    await _send_through(stub, tls="none")

    assert "STARTTLS" not in stub.commands
    assert len(stub.messages) == 1


async def test_credentials_are_sent_when_configured() -> None:
    stub = StubSmtp()

    await _send_through(stub, username="user", password="secret")

    assert "AUTH" in stub.commands


@pytest.mark.parametrize(
    ("replies", "error"),
    [
        ({"rcpt": "550 no such user"}, MailDeliveryPermanentError),
        ({"rcpt": "553 bad mailbox"}, MailDeliveryPermanentError),
        ({"rcpt": "451 try later"}, MailDeliveryTemporaryError),
        ({"data": "554 rejected"}, MailDeliveryPermanentError),
        ({"data": "452 mailbox full"}, MailDeliveryTemporaryError),
        ({"mail_from": "553 sender not allowed"}, MailDeliveryTemporaryError),
        ({"mail_from": "451 later"}, MailDeliveryTemporaryError),
    ],
    ids=[
        "recipient_550",
        "recipient_553",
        "recipient_451",
        "data_554",
        "data_452",
        "sender_553",
        "sender_451",
    ],
)
async def test_server_replies_are_sorted_into_temporary_and_permanent(
    replies: dict[str, Any], error: type[Exception]
) -> None:
    with pytest.raises(error):
        await _send_through(StubSmtp(**replies))


async def test_rejected_login_is_temporary() -> None:
    with pytest.raises(MailDeliveryTemporaryError) as caught:
        await _send_through(StubSmtp(auth="535 bad credentials"), username="u", password="p")

    assert "535" in str(caught.value)


async def test_closed_port_is_temporary() -> None:
    mailer = SmtpMailer(MailSection(host="127.0.0.1", port=1))

    with pytest.raises(MailDeliveryTemporaryError):
        await mailer.send("anna@example.org", "Анна", EmailPurpose.EMAIL_CONFIRM, CONFIRM_LINK)


async def test_tls_against_a_plain_server_is_temporary() -> None:
    with pytest.raises(MailDeliveryTemporaryError):
        await _send_through(StubSmtp(), tls="tls")


async def test_slow_server_is_cut_by_the_total_budget() -> None:
    started = time.monotonic()

    with pytest.raises(MailDeliveryTemporaryError) as caught:
        await _send_through(StubSmtp(delay=0.4), timeout_seconds=1.0)

    assert time.monotonic() - started < 1.8
    assert isinstance(caught.value.__cause__, TimeoutError)


async def test_errors_reveal_neither_address_nor_server_text() -> None:
    with pytest.raises(MailDeliveryPermanentError) as caught:
        await _send_through(StubSmtp(rcpt="550 anna@example.org does not exist here"))

    assert "anna@example.org" not in str(caught.value)
    assert "does not exist" not in str(caught.value)


@pytest.fixture(scope="module")
def certificate(tmp_path_factory: pytest.TempPathFactory) -> Path:
    folder = tmp_path_factory.mktemp("mailpit-tls")
    openssl = shutil.which("openssl")
    assert openssl is not None
    subprocess.run(
        [
            openssl,
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-days",
            "1",
            "-subj",
            "/CN=localhost",
            "-addext",
            "subjectAltName=DNS:localhost,IP:127.0.0.1",
            "-keyout",
            str(folder / "key.pem"),
            "-out",
            str(folder / "cert.pem"),
        ],
        check=True,
        capture_output=True,
    )
    (folder / "auth.txt").write_text(f"{SMTP_USER}:{SMTP_PASSWORD}\n")
    for path in folder.iterdir():
        path.chmod(0o644)
    folder.chmod(0o755)
    return folder


@pytest.fixture(scope="module")
def mailpit(certificate: Path) -> Iterator[DockerContainer]:
    container = (
        DockerContainer(MAILPIT_IMAGE)
        .with_volume_mapping(str(certificate), "/certs", "ro")
        .with_command(
            "--smtp-tls-cert /certs/cert.pem --smtp-tls-key /certs/key.pem"
            " --smtp-require-tls --smtp-auth-file /certs/auth.txt"
        )
        .with_exposed_ports(1025, 8025)
        .waiting_for(HttpWaitStrategy(8025, "/readyz").for_status_code(200))
    )
    with container:
        yield container


def _mailpit_settings(container: DockerContainer, **overrides: Any) -> MailSection:
    values: dict[str, Any] = {
        "host": "localhost",
        "port": int(container.get_exposed_port(1025)),
        "tls": "tls",
        "username": SMTP_USER,
        "password": SMTP_PASSWORD,
    }
    return MailSection(**(values | overrides))


def _received(container: DockerContainer) -> list[dict[str, Any]]:
    url = f"http://localhost:{container.get_exposed_port(8025)}/api/v1/messages"
    with urllib.request.urlopen(url) as response:
        messages: list[dict[str, Any]] = json.load(response)["messages"]
    return messages


@pytest.fixture
def trusted(certificate: Path) -> ssl.SSLContext:
    return ssl.create_default_context(cafile=str(certificate / "cert.pem"))


async def _send_to_mailpit(mailer: SmtpMailer) -> None:
    await mailer.send("tls@example.org", "Анна", EmailPurpose.EMAIL_CONFIRM, CONFIRM_LINK)


async def test_mailpit_accepts_tls_with_password(
    mailpit: DockerContainer, trusted: ssl.SSLContext
) -> None:
    before = len(_received(mailpit))

    await _send_to_mailpit(SmtpMailer(_mailpit_settings(mailpit), tls_context=trusted))

    received = _received(mailpit)
    assert len(received) == before + 1
    assert received[0]["Subject"] == "Подтвердите адрес почты"


async def test_mailpit_rejects_a_wrong_password_as_temporary(
    mailpit: DockerContainer, trusted: ssl.SSLContext
) -> None:
    mailer = SmtpMailer(_mailpit_settings(mailpit, password="wrong"), tls_context=trusted)

    with pytest.raises(MailDeliveryTemporaryError):
        await _send_to_mailpit(mailer)


async def test_plain_client_cannot_talk_to_tls_only_server(mailpit: DockerContainer) -> None:
    before = len(_received(mailpit))
    mailer = SmtpMailer(_mailpit_settings(mailpit, tls="none"), timeout_seconds=2.0)

    with pytest.raises(MailDeliveryTemporaryError):
        await _send_to_mailpit(mailer)

    assert len(_received(mailpit)) == before


async def test_unknown_certificate_is_refused_by_default(mailpit: DockerContainer) -> None:
    before = len(_received(mailpit))

    with pytest.raises(MailDeliveryTemporaryError) as caught:
        await _send_to_mailpit(SmtpMailer(_mailpit_settings(mailpit)))

    assert isinstance(caught.value.__cause__, OSError)
    assert len(_received(mailpit)) == before
