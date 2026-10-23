from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy import text

from app.core.config import get_settings
from app.core.db import SessionFactory


@asynccontextmanager
async def lifespan(app: FastAPI):
    import redis.asyncio as aioredis

    settings = get_settings()
    app.state.redis = await aioredis.from_url(
        settings.redis_url, decode_responses=True, socket_connect_timeout=2)
    try:
        yield
    finally:
        await app.state.redis.aclose()


def _ensure_owner_user(settings) -> None:
    """Seed the single owner account exactly once (idempotent)."""
    from app.models import User

    with SessionFactory() as db:
        if db.query(User).count() == 0:
            db.add(User(
                email=settings.owner_email,
                password_hash="!disabled",  # nosec B106 – not a credential, schema compat
                is_active=True,
                email_verified=True,
            ))
            db.commit()


def create_app() -> FastAPI:
    settings = get_settings()

    app = FastAPI(
        title="Sentinel API",
        description="Authorized web vulnerability monitoring — detect, verify, "
                    "explain, disclose.",
        version="1.0.0",
        lifespan=lifespan,
        docs_url="/docs" if settings.enable_docs else None,
        redoc_url=None,
        openapi_url="/openapi.json" if settings.enable_docs else None,
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origin_list,
        allow_credentials=False,
        allow_methods=["GET", "POST", "PATCH", "PUT", "DELETE"],
        allow_headers=["content-type"],
        max_age=600,
    )

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Permissions-Policy"] = "geolocation=(), camera=(), microphone=()"
        response.headers["Server"] = "sentinel"
        return response

    _ensure_owner_user(settings)

    @app.exception_handler(HTTPException)
    async def http_error(request: Request, exc: HTTPException):
        detail = exc.detail
        headers = getattr(exc, "headers", None) or {}
        if isinstance(detail, dict):
            code = detail.get("code", "ERROR")
            message = detail.get("message", "Request failed.")
        else:
            code, message = "ERROR", str(detail)
        return JSONResponse(status_code=exc.status_code, content={
            "error": {"code": code, "message": message}}, headers=headers)

    @app.exception_handler(Exception)
    async def internal_error(request: Request, exc: Exception):
        logging.getLogger("sentinel.api").exception("internal error")
        return JSONResponse(status_code=500, content={
            "error": {"code": "INTERNAL_ERROR",
                      "message": "An internal error occurred. It has been logged."}})

    @app.get("/health", tags=["ops"])
    def health():
        return {"status": "ok", "app": "sentinel", "api_version": "1.0.0"}

    @app.get("/ready", tags=["ops"])
    def ready():
        db_ok, redis_ok = False, False
        detail = {"database": "fail", "redis": "fail"}
        try:
            with SessionFactory() as db:
                db.execute(text("SELECT 1"))
            db_ok, detail["database"] = True, "ok"
        except Exception as exc:
            logging.getLogger("sentinel.api").error("db unready: %s", type(exc).__name__)
        try:
            import redis

            r = redis.Redis.from_url(settings.redis_url, socket_connect_timeout=2)
            r.ping()
            r.close()
            redis_ok, detail["redis"] = True, "ok"
        except Exception as exc:
            logging.getLogger("sentinel.api").error("redis unready: %s",
                                                    type(exc).__name__)
        status_code = 200 if db_ok and redis_ok else 503
        return JSONResponse(status_code=status_code, content={
            "status": "ready" if db_ok and redis_ok else "not_ready",
            "checks": detail,
        })

    from app.api.routers import (
        assets,
        audit,
        contacts,
        disclosures,
        findings,
        metrics,
        notifications,
        reports,
        scans,
    )

    app.include_router(assets.router, prefix="/api")
    app.include_router(scans.router, prefix="/api")
    app.include_router(scans.router2, prefix="/api")
    app.include_router(findings.router, prefix="/api")
    app.include_router(contacts.router, prefix="/api")
    app.include_router(disclosures.draft_router, prefix="/api")
    app.include_router(disclosures.router, prefix="/api")
    app.include_router(reports.router, prefix="/api")
    app.include_router(notifications.router, prefix="/api")
    app.include_router(audit.router, prefix="/api")
    app.include_router(metrics.router, prefix="/api")

    return app


app = create_app()
