from __future__ import annotations

import uuid

from fastapi import Depends, HTTPException, Request
from fastapi.security import HTTPBearer
from sqlalchemy.orm import Session

from app.core.db import get_db
from app.core.security import CSRF_COOKIE, SESSION_COOKIE, session_from_token
from app.models import Asset, User, UserSession

_bearer = HTTPBearer(auto_error=False)


def get_session(request: Request, db: Session = Depends(get_db)) -> tuple[User, UserSession]:
    raw = request.cookies.get(SESSION_COOKIE)
    header = request.headers.get("authorization")
    if header and header.lower().startswith("bearer "):
        raw = header.split(" ", 1)[1].strip()
    session = session_from_token(db, raw or "")
    if session is None:
        raise HTTPException(
            status_code=401,
            detail={"code": "UNAUTHENTICATED", "message": "Authentication required."},
        )
    user = db.get(User, session.user_id)
    if user is None or not user.is_active:
        raise HTTPException(status_code=401,
                            detail={"code": "UNAUTHENTICATED",
                                    "message": "User is inactive."})
    return user, session


def get_current_user(pair=Depends(get_session)) -> User:
    return pair[0]


def require_csrf(request: Request, pair=Depends(get_session)) -> None:
    """Double-submit CSRF check for cookie-authenticated mutating requests."""
    if request.method in ("GET", "HEAD", "OPTIONS"):
        return
    auth_header = request.headers.get("authorization", "")
    cookie_auth = pair[1] is not None and not auth_header
    if not cookie_auth:
        return
    cookie_token = request.cookies.get(CSRF_COOKIE)
    header_token = request.headers.get("x-csrf-token")
    if not cookie_token or not header_token or cookie_token != header_token:
        raise HTTPException(
            status_code=403,
            detail={"code": "CSRF_INVALID", "message": "CSRF validation failed."},
        )


def get_user_asset_or_403(db: Session, user: User, asset_id: str) -> Asset:
    try:
        asset_uuid = uuid.UUID(str(asset_id))
    except (ValueError, AttributeError, TypeError):
        raise HTTPException(status_code=404, detail={"code": "NOT_FOUND",
                                                     "message": "Asset not found."})
    asset = db.get(Asset, asset_uuid)
    if asset is None or asset.user_id != user.id:
        raise HTTPException(status_code=404, detail={"code": "NOT_FOUND",
                                                     "message": "Asset not found."})
    return asset


def require_authorized_asset(asset: Asset) -> Asset:
    if not asset.authorization_confirmed:
        raise HTTPException(
            status_code=409,
            detail={"code": "AUTHORIZATION_REQUIRED",
                    "message": "Testing authorization must be confirmed for this asset."},
        )
    return asset
