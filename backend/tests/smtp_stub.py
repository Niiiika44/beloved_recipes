import asyncio
from email import message_from_bytes, policy
from email.message import EmailMessage


class StubSmtp:
    def __init__(
        self,
        mail_from: str = "250 OK",
        rcpt: str = "250 OK",
        data: str = "250 OK",
        auth: str = "235 OK",
        delay: float = 0.0,
    ) -> None:
        self.replies = {"MAIL": mail_from, "RCPT": rcpt, "AUTH": auth}
        self.data_reply = data
        self.delay = delay
        self.commands: list[str] = []
        self.messages: list[EmailMessage] = []

    async def _say(self, writer: asyncio.StreamWriter, line: str) -> None:
        await asyncio.sleep(self.delay)
        writer.write((line + "\r\n").encode())
        await writer.drain()

    async def handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        await self._say(writer, "220 stub")
        while line := await reader.readline():
            verb = line.decode(errors="replace").split(" ")[0].strip().upper()
            self.commands.append(verb)
            if verb == "EHLO":
                writer.write(
                    b"250-stub\r\n250-STARTTLS\r\n250-AUTH PLAIN LOGIN\r\n250 8BITMIME\r\n"
                )
                await writer.drain()
            elif verb in self.replies:
                await self._say(writer, self.replies[verb])
            elif verb == "DATA":
                await self._say(writer, "354 go")
                body = b""
                while (chunk := await reader.readline()) not in (b".\r\n", b""):
                    body += chunk
                parsed = message_from_bytes(body, policy=policy.default)
                assert isinstance(parsed, EmailMessage)
                self.messages.append(parsed)
                await self._say(writer, self.data_reply)
            elif verb == "QUIT":
                await self._say(writer, "221 bye")
                break
            else:
                await self._say(writer, "502 not here")
        writer.close()
