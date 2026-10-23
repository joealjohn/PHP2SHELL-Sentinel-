from __future__ import annotations

from app.api import deps
from app.core.db import get_db
from app.core.rate_limit import enforce
from app.models import Asset, Finding, Scan, User, utcnow
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy.orm import Session

router = APIRouter(prefix="/scans", tags=["scans"])


@router.get("")
def list_scans(db: Session = Depends(get_db),
               user: User = Depends(deps.get_current_user),
               asset_id: str | None = None, limit: int = Query(50, le=200)):
    q = db.query(Scan).filter(Scan.user_id == user.id)
    if asset_id:
        from app.api import deps as d
        d.get_user_asset_or_403  # noqa: B018
        try:
            from uuid import UUID as U
            aid = U(asset_id)
        except ValueError:
            return {"scans": []}
        q = q.filter(Scan.asset_id == aid)
    scans = q.order_by(Scan.created_at.desc()).limit(limit).all()
    return {"scans": [s.to_json() for s in scans]}


@router.get("/{scan_id}")
def get_scan(scan_id: str, db: Session = Depends(get_db),
             user: User = Depends(deps.get_current_user)):
    scan = _own_scan_or_404(db, user, scan_id)
    summary = {"asset_name": (db.get(Asset, scan.asset_id).name if db.get(Asset, scan.asset_id) else None)}
    data = scan.to_json()
    data["asset_name"] = summary["asset_name"]
    return data


def _own_scan_or_404(db: Session, user: User, scan_id: str) -> Scan:
    import uuid
    try:
        sid = uuid.UUID(scan_id)
    except (ValueError, TypeError):
        raise HTTPException(status_code=404, detail={"code": "NOT_FOUND",
                                                     "message": "Scan not found."})
    scan = db.get(Scan, sid)
    if scan is None or scan.user_id != user.id:
        raise HTTPException(status_code=404, detail={"code": "NOT_FOUND",
                                                     "message": "Scan not found."})
    return scan


@router.post("/{scan_id}/cancel")
def cancel_scan(scan_id: str, request: Request, db: Session = Depends(get_db),
                user: User = Depends(deps.get_current_user)):
    enforce(request, action="scan-cancel", max_requests=20, window_seconds=300)
    scan = _own_scan_or_404(db, user, scan_id)
    if scan.status in ("COMPLETED", "FAILED"):
        raise HTTPException(status_code=409, detail={
            "code": "SCAN_FINISHED", "message": "This scan already finished."})
    scan.status = "FAILED"
    scan.error = "Cancelled by user"
    scan.completed_at = utcnow()
    db.commit()
    return scan.to_json()


router2 = APIRouter(tags=["findings"])


@router2.get("/scan/{scan_id}/findings")
def scan_findings(scan_id: str, db: Session = Depends(get_db),
                  user: User = Depends(deps.get_current_user)):
    scan = _own_scan_or_404(db, user, scan_id)
    findings = db.query(Finding).filter(Finding.scan_id == scan.id).all()
    return {"findings": [f.to_json() for f in findings]}
