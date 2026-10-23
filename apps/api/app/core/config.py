from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    app_name: str = "Sentinel API"
    database_url: str = "postgresql+psycopg2://sentinel:sentinel@db:5432/sentinel"
    redis_url: str = "redis://redis:6379/0"
    session_secret: str = "dev-not-secret"
    session_ttl_days: int = 14
    cookie_secure: bool = False
    cors_origins: str = "http://localhost:3000"

    smtp_host: str = "mailpit"
    smtp_port: int = 1025
    smtp_username: str = ""
    smtp_password: str = ""
    smtp_from: str = "sentinel@sentinel.local"
    smtp_tls: bool = False

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


@lru_cache
def get_settings() -> Settings:
    return Settings()
