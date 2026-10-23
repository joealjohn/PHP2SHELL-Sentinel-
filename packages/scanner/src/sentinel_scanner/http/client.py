from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass
from typing import Self
from urllib.parse import urljoin, urlsplit

import httpx
from sentinel_shared.redaction import redact_headers
from sentinel_shared.urlguard import (
    TargetValidationError,
    normalize_url,
    resolve_host,
)

from sentinel_scanner.core.config import ScannerConfig
from sentinel_scanner.core.errors import ScanError, ScanTargetError
from sentinel_scanner.models import FetchResult, RedirectHop

_USER_AGENT_HEADER = "User-Agent"


@dataclass
class FetchOutcome:
    ok: bool
    status_code: int = 0
    error: str = ""
    result: FetchResult | None = None
    error_code: str = ""


class _RateLimiter:
    def __init__(self, rate_per_second: float) -> None:
        self._min_interval = 1.0 / rate_per_second if rate_per_second > 0 else 0.0
        self._last = 0.0
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        if self._min_interval <= 0:
            return
        async with self._lock:
            now = time.monotonic()
            wait = self._last + self._min_interval - now
            if wait > 0:
                await asyncio.sleep(wait)
            self._last = time.monotonic()


class SentinelHttpClient:
    """Non-destructive, bounded, SSRF-safe HTTP fetcher.

    Rules enforced on every hop of every request:
    - scheme http/https only
    - hostname resolved via DNS and every answer verified as public
    - redirects followed manually with full revalidation per hop
    - response body size capped
    - cookies never stored or recorded (Set-Cookie is counted, then dropped)
    - user agent reflects the Sentinel security scanner; no browser spoofing
    """

    def __init__(self, config: ScannerConfig | None = None) -> None:
        self.config = config or ScannerConfig()
        self._rate = _RateLimiter(self.config.rate_limit)
        self._sem: asyncio.Semaphore | None = None
        self._client: httpx.AsyncClient | None = None
        self._requests_made = 0

    async def __aenter__(self) -> Self:
        self._sem = asyncio.Semaphore(max(1, self.config.concurrency))
        self._client = httpx.AsyncClient(
            follow_redirects=False,
            timeout=httpx.Timeout(
                connect=self.config.connect_timeout,
                read=self.config.read_timeout,
                write=self.config.connect_timeout,
                pool=self.config.connect_timeout,
            ),
            limits=httpx.Limits(max_connections=max(2, self.config.concurrency)),
            verify=True,
            http2=False,
        )
        return self

    async def __aexit__(self, *_args: object) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    async def close(self) -> None:
        await self.__aexit__(None, None, None)

    @property
    def requests_made(self) -> int:
        return self._requests_made

    async def get(self, url: str, *, follow_redirects: bool = True) -> FetchOutcome:
        """GET a target after validating it. Per-hop validation, redirect cap, size cap."""
        if self._client is None or self._sem is None:
            raise ScanError("SentinelHttpClient not started (use async with)")

        try:
            current = self._normalize_hop(url)
        except ScanTargetError as exc:
            return FetchOutcome(ok=False, error_code="TARGET_VALIDATION_FAILED",
                                error=exc.message)
        redirect_chain: list[RedirectHop] = []
        visited: set[str] = set()

        for hop_index in range(self.config.max_redirects + 1):
            if current in visited:
                return FetchOutcome(ok=False, error_code="REDIRECT_LOOP",
                                    error="Redirect loop detected and aborted.")
            visited.add(current)

            parsed = urlsplit(current)
            host = parsed.hostname or ""
            try:
                resolved = resolve_host(host, timeout=self.config.connect_timeout)
            except TargetValidationError as exc:
                return FetchOutcome(ok=False, error_code="TARGET_VALIDATION_FAILED",
                                    error=exc.message)
            if not self.config.allow_private_targets and not resolved.all_public:
                return FetchOutcome(ok=False, error_code="TARGET_VALIDATION_FAILED",
                                    error="The target resolves to a private network address.")

            await self._rate.acquire()
            async with self._sem:
                try:
                    resp = await self._client.get(
                        current,
                        follow_redirects=False,
                        headers={
                            _USER_AGENT_HEADER: self.config.user_agent,
                            "Accept": "text/html,application/xhtml+xml;q=0.8,*/*;q=0.5",
                            "Accept-Language": "en",
                            "Connection": "close",
                        },
                    )
                except (httpx.TimeoutException, httpx.TransportError) as exc:
                    return FetchOutcome(ok=False, error_code="UNREACHABLE",
                                        error=f"type={type(exc).__name__} detail={exc}")
                self._requests_made += 1

            headers = _sanitize_headers(dict(resp.headers))
            set_cookie_count = sum(1 for k in resp.headers if k.lower() == "set-cookie")
            body_text, _truncated = await self._bounded_body(resp)

            if resp.status_code in (301, 302, 303, 307, 308):
                location = headers.get("Location") or headers.get("location")
                hops = resp.headers.get_list("location")
                if not location or not hops:
                    return FetchOutcome(ok=False, error_code="UNREACHABLE",
                                        error=f"Redirect without Location at {current}",
                                        result=FetchResult(
                                            url=url, final_url=current,
                                            status_code=resp.status_code,
                                            headers=headers, body_text=body_text,
                                            body_len=len(body_text.encode("utf-8", "ignore")),
                                            elapsed_ms=int(
                                                resp.elapsed.total_seconds() * 1000
                                            ) if resp.elapsed else 0))
                store_hop = RedirectHop(url=current, status_code=resp.status_code,
                                        location=location)
                if not redirect_chain or redirect_chain[-1] != store_hop:
                    redirect_chain.append(store_hop)
                if not follow_redirects or len(redirect_chain) >= self.config.max_redirects + 1:
                    return self._outcome(url, current, resp.status_code, headers, body_text,
                                         redirect_chain, set_cookie_count)
                target = urljoin(current, location.strip())
                try:
                    current = self._normalize_hop(target)
                except ScanTargetError as exc:
                    return FetchOutcome(ok=False, error_code="TARGET_VALIDATION_FAILED",
                                        error=exc.message,
                                        result=FetchResult(
                                            url=url, final_url=current,
                                            status_code=resp.status_code,
                                            headers=headers, redirect_chain=redirect_chain,
                                            set_cookie_count=set_cookie_count))
                if _redirect_schemes_differ_unsafely(urlsplit(target).scheme):
                    return FetchOutcome(ok=False, error_code="TARGET_VALIDATION_FAILED",
                                        error="Redirect to an unsupported scheme.",
                                        result=FetchResult(
                                            url=url, final_url=current,
                                            status_code=resp.status_code,
                                            headers=headers, redirect_chain=redirect_chain,
                                            set_cookie_count=set_cookie_count))
                continue

            return self._outcome(url, current, resp.status_code, headers, body_text,
                                 redirect_chain, set_cookie_count)

        return FetchOutcome(ok=False, error_code="TOO_MANY_REDIRECTS",
                            error=f"Exceeded {self.config.max_redirects} redirects.")

    @staticmethod
    def _normalize_hop(url: str) -> str:
        try:
            normalized = normalize_url(url)
        except TargetValidationError as exc:
            raise ScanTargetError(exc.code, exc.message) from exc
        return normalized

    async def _bounded_body(self, resp: httpx.Response) -> tuple[str, bool]:
        content = resp.content or b""
        truncated = len(content) > self.config.max_response_size
        if truncated:
            content = content[: self.config.max_response_size]
        charset = resp.charset_encoding or "utf-8"
        try:
            return content.decode(charset, errors="replace"), truncated
        except (LookupError, ValueError):
            return content.decode("utf-8", errors="replace"), truncated

    def _outcome(
        self,
        original_url: str,
        final_url: str,
        status: int,
        headers: dict[str, str],
        body_text: str,
        redirect_chain: list[RedirectHop],
        set_cookie_count: int | None = None,
    ) -> FetchOutcome:
        headers_case = {k.lower(): v for k, v in headers.items()}
        content_length = headers_case.get("content-length")
        body_len = len(body_text.encode("utf-8", "ignore"))
        if content_length and content_length.isdigit():
            body_len = min(body_len, int(content_length)) or body_len
        if set_cookie_count is None:
            set_cookie_count = sum(1 for h in headers_case if h == "set-cookie")
        return FetchOutcome(
            ok=True,
            status_code=status,
            result=FetchResult(
                url=original_url,
                final_url=final_url,
                status_code=status,
                headers=headers_case,
                body_text=body_text,
                body_len=body_len,
                content_type=headers_case.get("content-type", ""),
                redirect_chain=redirect_chain,
                set_cookie_count=set_cookie_count,
            ),
        )


def _sanitize_headers(headers: dict[str, str]) -> dict[str, str]:
    redacted = redact_headers(headers)
    return {k.lower(): v for k, v in redacted.items()}


def _redirect_schemes_differ_unsafely(scheme: str) -> bool:
    return scheme.lower() not in ("http", "https")
