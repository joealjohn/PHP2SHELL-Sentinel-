from __future__ import annotations

import contextlib
import re
from dataclasses import dataclass


@dataclass(frozen=True)
class EmailMessage:
    to_email: str
    subject: str
    body_text: str


def sanitize_header_value(value: str) -> str:
    """Strip CR/LF so user-editable fields cannot inject extra headers."""
    return re.sub(r"[\r\n]+", " ", str(value)).strip()


def validate_recipient(address: str) -> str:
    from email_validator import validate_email

    normalized = validate_email(address, check_deliverability=False).email
    return sanitize_header_value(normalized)


class EmailProvider:
    """Abstract email transport. Implementations keep credentials server-side."""

    async def send(self, message: EmailMessage) -> str:
        raise NotImplementedError


class SMTPProvider(EmailProvider):
    def __init__(self, host: str, port: int, username: str, password: str, sender: str,
                 tls: bool, starttls: bool = False) -> None:
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.sender = sanitize_header_value(sender)
        self.tls = tls
        self.starttls = starttls

    def _mime(self, message: EmailMessage) -> str:
        from email.message import EmailMessage as MIMEEmail
        from email.utils import formatdate

        mime = MIMEEmail()
        mime["From"] = self.sender
        mime["To"] = validate_recipient(message.to_email)
        mime["Subject"] = sanitize_header_value(message.subject)
        mime["Date"] = formatdate(localtime=False)
        mime["Message-ID"] = ""
        del mime["Message-ID"]
        mime.set_content(message.body_text)
        return mime.as_string()

    async def send(self, message: EmailMessage) -> str:
        import aiosmtplib

        recipient = validate_recipient(message.to_email)
        smtp = aiosmtplib.SMTP(
            hostname=self.host, port=self.port, timeout=30,
            use_tls=self.tls,
            start_tls=False if self.tls else self.starttls,
        )
        await smtp.connect()
        try:
            if self.username and self.password:
                await smtp.login(self.username, self.password)
            await smtp.sendmail(self.sender, [recipient], self._mime(message))
        finally:
            with contextlib.suppress(Exception):
                await smtp.quit()
        return "OK"


class NullProvider(EmailProvider):
    """Provider used when SMTP is disabled (SMTP_HOST empty)."""

    async def send(self, message: EmailMessage) -> str:
        return "SMTP_DISABLED"


_PROVIDER: EmailProvider | None = None


def get_email_provider() -> EmailProvider:
    global _PROVIDER
    if _PROVIDER is None:
        from app.core.config import get_settings
        s = get_settings()
        if not s.smtp_host:
            _PROVIDER = NullProvider()
        else:
            _PROVIDER = SMTPProvider(
                s.smtp_host, s.smtp_port, s.smtp_username, s.smtp_password,
                s.smtp_from, s.smtp_tls, s.smtp_starttls)
    return _PROVIDER


def reset_provider() -> None:
    global _PROVIDER
    _PROVIDER = None
