from __future__ import annotations

import re

REDACTED = "[REDACTED]"

SENSITIVE_HEADERS = {
    "authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "x-auth-token",
    "x-csrf-token",
    "api-key",
    "x-smtp",
}

_KEY_VALUE_TOKEN = re.compile(
    r"(?i)\b(Authorization|Bearer|X-Api-Key|Password|Token|Set-Cookie)\b\s*[:=]\s*([^\s;\"']+)"
)


def redact_headers(headers: dict[str, str]) -> dict[str, str]:
    out: dict[str, str] = {}
    for name, value in headers.items():
        if name.lower() in SENSITIVE_HEADERS:
            out[name] = REDACTED
        else:
            out[name] = value
    return out


def redact_text(text: str) -> str:
    if not text:
        return text
    return _KEY_VALUE_TOKEN.sub(lambda m: f"{m.group(1)[:1]}***={REDACTED}", text)
