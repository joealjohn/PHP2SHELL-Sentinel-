from __future__ import annotations

import pytest
from fastapi import HTTPException
from starlette.requests import Request


def _request(peer: str = "10.0.0.5", xff: str | None = None) -> Request:
    headers = []
    if xff is not None:
        headers.append((b"x-forwarded-for", xff.encode()))
    return Request({
        "type": "http",
        "http_version": "1.1",
        "method": "GET",
        "path": "/",
        "headers": headers,
        "client": (peer, 1234),
        "scheme": "http",
        "server": ("testserver", 80),
    })


@pytest.fixture()
def trusted_proxy(monkeypatch):
    from app.core.config import get_settings

    monkeypatch.setenv("TRUST_PROXY_HEADERS", "1")
    monkeypatch.setenv("TRUSTED_PROXY_IPS", "10.0.0.0/8")
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


class TestClientIpTrust:
    def test_xff_ignored_by_default(self):
        from app.core.rate_limit import client_ip

        assert client_ip(_request(peer="10.0.0.5", xff="203.0.113.9")) == "10.0.0.5"

    def test_xff_honoured_from_trusted_proxy(self, trusted_proxy):
        from app.core.rate_limit import client_ip

        assert client_ip(_request(peer="10.0.0.5", xff="203.0.113.9")) == "203.0.113.9"

    def test_xff_rejected_from_untrusted_peer(self, trusted_proxy):
        from app.core.rate_limit import client_ip

        assert client_ip(_request(peer="192.168.1.9", xff="203.0.113.9")) == "192.168.1.9"

    def test_garbage_xff_value_ignored(self, trusted_proxy):
        from app.core.rate_limit import client_ip

        assert client_ip(_request(peer="10.0.0.5", xff="not-an-ip")) == "10.0.0.5"


class TestRateLimitFailClosed:
    def test_sensitive_action_unavailable_redis(self, monkeypatch):
        from app.core import rate_limit

        monkeypatch.setattr(rate_limit, "_redis", lambda: None)
        with pytest.raises(HTTPException) as exc:
            rate_limit.enforce(_request(), action="login", max_requests=5,
                               window_seconds=60, fail_closed=True)
        assert exc.value.status_code == 503

    def test_non_sensitive_action_fails_open(self, monkeypatch):
        from app.core import rate_limit

        monkeypatch.setattr(rate_limit, "_redis", lambda: None)
        rate_limit.enforce(_request(), action="scan", max_requests=5,
                           window_seconds=60, fail_closed=False)


class TestMiscHardening:
    def test_docs_disabled_by_default(self, client):
        assert client.get("/docs").status_code == 404
        assert client.get("/openapi.json").status_code == 404


class TestEmailHardening:
    def test_header_sanitisation(self):
        from app.services.email import sanitize_header_value

        assert sanitize_header_value("Hello\r\nBcc: evil@example.com") == (
            "Hello Bcc: evil@example.com")

    def test_recipient_validation(self):
        from app.services.email import validate_recipient
        from email_validator import EmailNotValidError

        assert validate_recipient("security@example.com") == "security@example.com"
        with pytest.raises(EmailNotValidError):
            validate_recipient("not-an-address\r\nBcc: x@example.com")

    def test_mime_has_no_injected_headers(self):
        from app.services.email import EmailMessage, SMTPProvider

        provider = SMTPProvider("mailpit", 1025, "", "", "sentinel@example.com",
                                tls=False, starttls=True)
        raw = provider._mime(EmailMessage(
            to_email="team@example.com",
            subject="Subject\r\nBcc: attacker@example.com",
            body_text="body"))
        assert "\nBcc: attacker" not in raw
        assert "Subject: Subject Bcc: attacker@example.com" in raw
        assert provider.starttls is True
