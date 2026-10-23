from __future__ import annotations

from datetime import UTC, datetime, timedelta

from app.api import deps
from app.core.config import get_settings
from app.core.db import get_db
from app.core.rate_limit import client_ip, enforce
from app.models import (
    Asset,
    Finding,
    Scan,
    User,
    utcnow,
)
from app.schemas.v1 import AssetIn, AssetOut, AssetUpdate
from app.services import observability
from fastapi import APIRouter, Depends, HTTPException, Request
from sentinel_shared.urlguard import TargetValidationError, assert_url_scannable
from sqlalchemy import func
from sqlalchemy.orm import Session

router = APIRouter(prefix="/assets", tags=["assets"],
                   dependencies=[Depends(deps.require_csrf)])


def _maybe_resolve_asset_out(db: Session, asset: Asset) -> AssetOut:
    out = AssetOut.model_validate(asset)
    out.open_findings = (
        db.query(func.count(Finding.id))
        .filter(Finding.asset_id == asset.id,
                Finding.status.notin_(["RESOLVED"]),
                Finding.state.notin_(["NOT_DETECTED", "PATCHED"]))
        .scalar()
    )
    last = (
        db.query(Scan).filter(Scan.asset_id == asset.id,
                              Scan.status.in_(["COMPLETED", "FAILED"]))
        .order_by(Scan.created_at.desc()).first()
    )
    out.last_scan_status = last.status if last else None
    return out


@router.get("")
def list_assets(db: Session = Depends(get_db), user: User = Depends(deps.get_current_user)):
    assets = (
        db.query(Asset).filter(Asset.user_id == user.id)
        .order_by(Asset.created_at.desc()).all()
    )
    out = [_maybe_resolve_asset_out(db, a) for a in assets]
    return {"assets": [o.to_json() for o in out]}


@router.post("", status_code=201)
def create_asset(payload: AssetIn, request: Request, db: Session = Depends(get_db),
                 user: User = Depends(deps.get_current_user)):
    enforce(request, action="asset-create", max_requests=30, window_seconds=3600)
    try:
        normalized, _target = assert_url_scannable(
            payload.url, allow_private=get_settings().allow_private_targets)
    except TargetValidationError as exc:
        raise HTTPException(status_code=422, detail={
            "code": exc.code, "message": exc.message,
        })
    from urllib.parse import urlsplit
    parsed = urlsplit(normalized)
    now = datetime.now(UTC)
    asset = Asset(
        user_id=user.id,
        name=payload.name.strip(),
        url=normalized,
        normalized_url=normalized,
        host=parsed.hostname or "",
        description=payload.description,
        authorization_confirmed=payload.authorization_confirmed,
        authorization_confirmed_at=now if payload.authorization_confirmed else None,
        scan_interval_seconds=payload.scan_interval_seconds,
        monitoring_enabled=payload.monitoring_enabled,
    )
    db.add(asset)
    db.flush()
    observability.audit(user_id=user.id, asset_id=asset.id, action="ASSET_CREATED",
                        resource_type="asset", resource_id=asset.id,
                        ip_address=client_ip(request), db=db)
    db.commit()
    return _maybe_resolve_asset_out(db, asset).to_json()


@router.get("/{asset_id}")
def get_asset(asset_id: str, db: Session = Depends(get_db),
              user: User = Depends(deps.get_current_user)):
    asset = deps.get_user_asset_or_403(db, user, asset_id)
    return _maybe_resolve_asset_out(db, asset).to_json()


@router.patch("/{asset_id}")
def update_asset(asset_id: str, payload: AssetUpdate, db: Session = Depends(get_db),
                 user: User = Depends(deps.get_current_user)):
    asset = deps.get_user_asset_or_403(db, user, asset_id)
    if payload.name is not None:
        asset.name = payload.name.strip()
    if payload.description is not None:
        asset.description = payload.description
    if payload.scan_interval_seconds is not None:
        asset.scan_interval_seconds = payload.scan_interval_seconds
        asset.next_scan_at = None
    if payload.monitoring_enabled is not None:
        asset.monitoring_enabled = payload.monitoring_enabled
    if payload.authorization_confirmed is not None:
        asset.authorization_confirmed = payload.authorization_confirmed
        asset.authorization_confirmed_at = datetime.now(UTC) \
            if payload.authorization_confirmed else None
        if payload.monitoring_enabled:
            base = asset.last_scan_at or utcnow()
            if asset.next_scan_at is None:
                asset.next_scan_at = base + timedelta(seconds=asset.scan_interval_seconds)
        else:
            asset.next_scan_at = None
    observability.audit(user_id=user.id, asset_id=asset.id, action="ASSET_UPDATED",
                        resource_type="asset", resource_id=asset.id,
                        detail={"monitoring_enabled": asset.monitoring_enabled})
    db.commit()
    return _maybe_resolve_asset_out(db, asset).to_json()


@router.delete("/{asset_id}")
def delete_asset(asset_id: str, db: Session = Depends(get_db),
                 user: User = Depends(deps.get_current_user),
                 ip: str = Depends(client_ip)):
    asset = deps.get_user_asset_or_403(db, user, asset_id)
    observability.audit(user_id=user.id, action="ASSET_DELETED", resource_type="asset",
                        resource_id=asset.id, detail={"url": asset.normalized_url},
                        ip_address=ip)
    db.delete(asset)
    db.commit()
    return {"ok": True}


@router.post("/{asset_id}/scan", status_code=202)
def start_scan(asset_id: str, request: Request, db: Session = Depends(get_db),
               user: User = Depends(deps.get_current_user)):
    enforce(request, action="scan-start", max_requests=10, window_seconds=300,
            user_scope=str(user.id))
    asset = deps.get_user_asset_or_403(db, user, asset_id)
    deps.require_authorized_asset(asset)
    running = (
        db.query(Scan)
        .filter(Scan.asset_id == asset.id, Scan.status.in_(["QUEUED", "SCANNING", "ANALYZING"]))
        .first()
    )
    if running:
        raise HTTPException(status_code=409, detail={
            "code": "SCAN_ALREADY_RUNNING",
            "message": "A scan is already queued or running for this asset.",
        })
    scan = Scan(asset_id=asset.id, user_id=user.id, status="QUEUED")
    db.add(scan)
    db.flush()
    observability.audit(user_id=user.id, asset_id=asset.id, action="SCAN_QUEUED",
                        resource_type="scan", resource_id=scan.id,
                        detail={"asset_url": asset.normalized_url},
                        ip_address=client_ip(request))
    db.commit()
    from app.workers.tasks import scan_asset
    task = scan_asset.apply_async(args=[str(scan.id)], task_id=str(scan.id))
    scan.celery_task_id = task.id
    db.commit()
    return {"scan_id": str(scan.id), "status": "QUEUED"}


@router.get("/{asset_id}/scans")
def asset_scans(asset_id: str, db: Session = Depends(get_db),
                user: User = Depends(deps.get_current_user)):
    asset = deps.get_user_asset_or_403(db, user, asset_id)
    scans = (
        db.query(Scan).filter(Scan.asset_id == asset.id)
        .order_by(Scan.created_at.desc()).limit(100).all()
    )
    return {"scans": [s.to_json() for s in scans]}
