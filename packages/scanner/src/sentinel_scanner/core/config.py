from __future__ import annotations

import os
from dataclasses import dataclass

DEFAULT_USER_AGENT = "SentinelSecurityScanner/1.0.0"


@dataclass(frozen=True)
class ScannerConfig:
    user_agent: str = DEFAULT_USER_AGENT
    total_timeout: float = 60.0
    connect_timeout: float = 10.0
    read_timeout: float = 30.0
    max_redirects: int = 8
    max_response_size: int = 2 * 1024 * 1024
    rate_limit: float = 5.0
    concurrency: int = 4
    allow_private_targets: bool = False

    @classmethod
    def from_env(cls, prefix: str = "SCAN_") -> ScannerConfig:
        g = os.getenv
        return cls(
            user_agent=g("SCANNER_USER_AGENT") or DEFAULT_USER_AGENT,
            total_timeout=float(g(f"{prefix}TIMEOUT") or 60),
            connect_timeout=float(g(f"{prefix}CONNECT_TIMEOUT") or 10),
            read_timeout=float(g(f"{prefix}READ_TIMEOUT") or 30),
            max_redirects=int(g(f"{prefix}MAX_REDIRECTS") or 8),
            max_response_size=int(g(f"{prefix}MAX_RESPONSE_SIZE") or 2 * 1024 * 1024),
            rate_limit=float(g(f"{prefix}RATE_LIMIT") or 5.0),
            concurrency=int(g(f"{prefix}CONCURRENCY") or 4),
            allow_private_targets=(g(f"{prefix}ALLOW_PRIVATE_TARGETS") or "0")
            .lower() in ("1", "true", "yes"),
        )
