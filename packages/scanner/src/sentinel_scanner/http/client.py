from __future__ import annotations

import asyncio
import logging
import ssl
import time
from dataclasses import dataclass
from typing import Self
from urllib.parse import urljoin, urlsplit

import certifi
import httpx
from sentinel_shared.redaction import redact_headers
from sentinel_shared.urlguard import (
    TargetValidationError,
    normalize_url,
    resolve_host,
)

from sentinel_scanner.core.config import ScannerConfig
from sentinel_scanner.core.errors import ScanError, ScanTargetError
from sentinel_scanner.http.tls import build_aia_ssl_context
from sentinel_scanner.models import FetchResult, RedirectHop

_USER_AGENT_HEADER = "User-Agent"
_log = logging.getLogger("sentinel.http")


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
        # True after AIA chasing has already been attempted for this client
        # instance, preventing infinite retry loops.
        self._aia_attempted = False

    async def __aenter__(self) -> Self:
        self._sem = asyncio.Semaphore(max(1, self.config.concurrency))
        # Build a strict SSL context backed by certifi's up-to-date CA bundle.
        # This improves intermediate-cert resolution without ever weakening
        # certificate verification — verify_mode stays CERT_REQUIRED.
        ssl_ctx = ssl.create_default_context(cafile=certifi.where())
        self._client = self._make_client(ssl_ctx)
        return self

    def _make_client(self, ssl_ctx: ssl.SSLContext) -> httpx.AsyncClient:
        """Create an httpx.AsyncClient with the given SSL context."""
        return httpx.AsyncClient(
            follow_redirects=False,
            timeout=httpx.Timeout(
                connect=self.config.connect_timeout,
                read=self.config.read_timeout,
                write=self.config.connect_timeout,
                pool=self.config.connect_timeout,
            ),
            limits=httpx.Limits(max_connections=max(2, self.config.concurrency)),
            verify=ssl_ctx,
            http2=False,
        )

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
                except httpx.ConnectError as exc:
                    # Distinguish TLS chain failures from generic connectivity
                    # problems so callers can report them with a clear diagnosis.
                    # Certificate verification is NEVER bypassed.
                    cause = exc.__cause__ or exc.__context__
                    if _is_tls_cert_error(cause):
                        if _is_hostname_mismatch_error(cause):
                            # The chain itself verified (possibly after AIA
                            # enrichment); the certificate simply does not
                            # cover the exact hostname in the URL - usually a
                            # "www." variant of the site's canonical host.
                            return FetchOutcome(
                                ok=False,
                                error_code="TLS_CERT_HOSTNAME_MISMATCH",
                                error=(
                                    f"TLS certificate is not valid for the exact "
                                    f"hostname {host!r} in {current!r}. Wildcard "
                                    f"certificates cover only one label - try the "
                                    f"site's canonical address (often without the "
                                    f"leading 'www.'). Sentinel never bypasses "
                                    f"certificate verification. detail={exc}"
                                ),
                            )
                        if not self._aia_attempted:
                            # Automatically chase AIA intermediate-cert URLs
                            # embedded in the server's own leaf certificate.
                            self._aia_attempted = True
                            port = urlsplit(current).port or 443
                            _log.info(
                                "sentinel.http: TLS chain incomplete for %s — "
                                "attempting AIA intermediate fetch", host
                            )
                            aia_ctx = await build_aia_ssl_context(host, port)
                            if aia_ctx is not None:
                                # Replace the httpx client with one that has
                                # the fetched intermediates loaded, then retry
                                # this hop transparently.
                                if self._client is not None:
                                    await self._client.aclose()
                                self._client = self._make_client(aia_ctx)
                                _log.info(
                                    "sentinel.http: AIA enrichment succeeded "
                                    "for %s — retrying hop", host
                                )
                                visited.discard(current)  # allow the retry
                                continue
                            _log.warning(
                                "sentinel.http: AIA chase found no intermediates "
                                "for %s", host
                            )
                        return FetchOutcome(
                            ok=False,
                            error_code="TLS_CERT_CHAIN_INCOMPLETE",
                            error=(
                                f"TLS certificate chain could not be verified for "
                                f"{current!r}. The server likely omits one or more "
                                f"intermediate certificates from its TLS handshake. "
                                f"Sentinel never bypasses certificate verification. "
                                f"detail={exc}"
                            ),
                        )
                    return FetchOutcome(ok=False, error_code="UNREACHABLE",
                                        error=f"type={type(exc).__name__} detail={exc}")
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


def _is_hostname_mismatch_error(exc: BaseException | None) -> bool:
    """Return True when the verification failure is specifically a
    hostname/name mismatch (the chain itself is otherwise complete).

    Distinguished from chain errors so users get the right fix: a wildcard
    certificate covers only one label, so e.g. ``www.exams.host`` will never
    match ``*.host`` even though the chain is fine.
    """
    seen: set[int] = set()
    node: BaseException | None = exc
    while node is not None and id(node) not in seen:
        seen.add(id(node))
        if isinstance(node, ssl.SSLCertVerificationError):
            text = str(getattr(node, "verify_message", "")) or str(node)
        elif isinstance(node, ssl.SSLError):
            text = str(node)
        else:
            node = node.__cause__ or node.__context__
            continue
        lowered = text.lower()
        if "hostname mismatch" in lowered or "certificate is not valid for" in lowered:
            return True
        node = node.__cause__ or node.__context__
    return False


def _is_tls_cert_error(exc: BaseException | None) -> bool:
    """Return True when *exc* (or its cause chain) is an SSL certificate error.

    httpx wraps low-level SSL failures inside ConnectError.  The actual
    ssl.SSLCertVerificationError may sit one or two levels deep in the
    __cause__ / __context__ chain, so we walk the whole chain.
    """
    seen: set[int] = set()
    node: BaseException | None = exc
    while node is not None and id(node) not in seen:
        seen.add(id(node))
        if isinstance(node, ssl.SSLCertVerificationError):
            return True
        # Also catch the parent ssl.SSLError with CERTIFICATE_VERIFY_FAILED
        if isinstance(node, ssl.SSLError) and "CERTIFICATE_VERIFY_FAILED" in str(node):
            return True
        node = node.__cause__ or node.__context__
    return False
