from __future__ import annotations

import ipaddress
import time

from fastapi import HTTPException, Request

_sync_redis = None


def _trusted_proxy(peer: str, entries: list[str]) -> bool:
    """True when the direct peer may assert X-Forwarded-For.

    An empty allow-list trusts every peer (proxy mode explicitly enabled);
    otherwise entries may be IP addresses or CIDR ranges.
    """
    if not entries:
        return True
    try:
        addr = ipaddress.ip_address(peer)
    except ValueError:
        return False
    for entry in entries:
        try:
            if "/" in entry:
                if addr in ipaddress.ip_network(entry, strict=False):
                    return True
            elif addr == ipaddress.ip_address(entry):
                return True
        except ValueError:
            continue
    return False


def client_ip(request: Request) -> str:
    """Best-effort client address.

    X-Forwarded-For is attacker-controlled unless a trusted reverse proxy
    overwrites it, so it is ignored by default (TRUST_PROXY_HEADERS=0).
    """
    from app.core.config import get_settings

    settings = get_settings()
    peer = request.client.host if request.client else ""
    if settings.trust_proxy_headers and _trusted_proxy(
            peer, settings.trusted_proxy_list):
        fwd = request.headers.get("x-forwarded-for")
        if fwd:
            candidate = fwd.split(",")[0].strip()
            try:
                return str(ipaddress.ip_address(candidate))[:60]
            except ValueError:
                pass
    return (peer or "unknown")[:60]


def _redis():
    global _sync_redis
    if _sync_redis is not None:
        return _sync_redis
    from app.core.config import get_settings

    settings = get_settings()
    try:
        import redis

        _sync_redis = redis.Redis.from_url(
            settings.redis_url, socket_connect_timeout=1, socket_timeout=1,
            decode_responses=True)
        _sync_redis.ping()
        return _sync_redis
    except Exception:
        _sync_redis = None
        return None


def enforce(request: Request, *, action: str, max_requests: int, window_seconds: int,
            fail_closed: bool = False) -> None:
    """Redis-backed fixed-window rate limiter.

    Fails open if Redis is unavailable by default; pass ``fail_closed=True``
    for sensitive actions so an outage cannot disable throttling.
    """
    redis_client = _redis()
    if redis_client is None:
        if fail_closed:
            raise HTTPException(
                status_code=503,
                detail={"code": "RATE_LIMIT_UNAVAILABLE",
                        "message": "Request throttling is unavailable. Try again shortly."},
            )
        return
    ip = client_ip(request)
    root = f"rl:{action}:{ip}"
    try:
        now = int(time.time())
        window_id = now // max(1, window_seconds)
        bucket = f"{root}:{window_id}"
        pipe = redis_client.pipeline()
        pipe.incr(bucket)
        pipe.expire(bucket, max(2, window_seconds))
        count, _ = pipe.execute()
        if count > max_requests:
            retry_after = (window_id + 1) * window_seconds - now
            raise HTTPException(
                status_code=429,
                detail={"code": "RATE_LIMITED",
                        "message": "Too many requests. Try again shortly."},
                headers={"Retry-After": str(max(1, retry_after))},
            )
    except HTTPException:
        raise
    except Exception:
        if fail_closed:
            raise HTTPException(
                status_code=503,
                detail={"code": "RATE_LIMIT_UNAVAILABLE",
                        "message": "Request throttling is unavailable. Try again shortly."},
            ) from None
        return
