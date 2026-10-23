from __future__ import annotations

import uuid

from fastapi import Depends, HTTPException
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.db import get_db
from app.models import Asset, User


def get_current_user(db: Session = Depends(get_db)) -> User:
    """Single-user deployment: every request operates on the local owner.

    The owner row is seeded at application startup; this fallback covers
    fresh databases and tests. ``password_hash`` is kept only for schema
    compatibility and is intentionally not a valid credential.
    """
    user = db.query(User).order_by(User.created_at).first()
    if user is None:
        user = User(
            email=get_settings().owner_email,
            password_hash="!disabled",  # nosec B106 – not a credential, schema compat
            is_active=True,
            email_verified=True,
        )
        db.add(user)
        db.commit()
    return user


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
