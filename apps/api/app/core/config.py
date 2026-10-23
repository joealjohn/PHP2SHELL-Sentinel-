from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    app_name: str = "Sentinel API"
    database_url: str = "postgresql+psycopg2://sentinel:sentinel@db:5432/sentinel"
    redis_url: str = "redis://redis:6379/0"
    # Single-user local deployment; no login is performed. This address is
    # the default disclosure test-email recipient and audit-log subject.
    owner_email: str = "owner@sentinel.local"
    cors_origins: str = "http://localhost:3000"

    # X-Forwarded-For is only honoured when the API sits behind a trusted
    # reverse proxy; otherwise any client could spoof its source IP and
    # bypass the rate limiter / poison the audit log.
    trust_proxy_headers: bool = False
    trusted_proxy_ips: str = ""

    # Keep interactive docs off in anything but local development.
    enable_docs: bool = False
    # When Redis is down, sensitive actions (login/register) refuse rather
    # than silently losing brute-force protection.
    rate_limit_fail_closed: bool = True

    smtp_host: str = "mailpit"
    smtp_port: int = 1025
    smtp_username: str = ""
    smtp_password: str = ""
    smtp_from: str = "sentinel@sentinel.local"
    smtp_tls: bool = False
    smtp_starttls: bool = False

    scanner_user_agent: str = "SentinelSecurityScanner/1.0.0"
    scan_timeout: float = 60.0
    scan_connect_timeout: float = 10.0
    scan_read_timeout: float = 30.0
    scan_max_redirects: int = 8
    scan_max_response_size: int = 2 * 1024 * 1024
    scan_rate_limit: float = 5.0
    scan_concurrency: int = 4

    @property
    def allow_private_targets(self) -> bool:
        import os
        return bool(os.getenv("SCAN_ALLOW_PRIVATE_TARGETS", "0").lower() in ("1", "true", "yes"))

    @property
    def cors_origin_list(self) -> list[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]

    @property
    def trusted_proxy_list(self) -> list[str]:
        return [p.strip() for p in self.trusted_proxy_ips.split(",") if p.strip()]


@lru_cache
def get_settings() -> Settings:
    return Settings()
