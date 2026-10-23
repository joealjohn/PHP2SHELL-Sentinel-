from __future__ import annotations

import re


def sanitize_detail(text: str, limit: int = 1200) -> str:
    """Strip credentials/tokens from error text before persistence."""
    if not text:
        return text
    text = text[:limit]
    text = re.sub(r"(?i)(password|token|authorization|cookie)\s*[:=]\s*\S+", r"\1=[REDACTED]", text)
    return text
