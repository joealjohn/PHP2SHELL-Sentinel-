from __future__ import annotations

import time

from fastapi import HTTPException, Request

_sync_redis = None


def client_ip(request: Request) -> str:
    fwd = request.headers.get("x-forwarded-for")
    if fwd:
        return fwd.split(",")[0].strip()[:60]
    ip = request.client.host if request.client else ""
    return ip[:60] or "unknown"


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
            user_scope: str | None = None) -> None:
    """Redis-backed fixed-window rate limiter. Fails open if Redis unavailable."""
    redis_client = _redis()
    if redis_client is None:
        return
    ip = client_ip(request)
    root = f"rl:{action}:{user_scope or ip}"
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
        return
