from __future__ import annotations

import uuid as uuid_lib

from app.api import deps
from app.core.db import get_db
from app.core.rate_limit import enforce
from app.models import Asset, Finding, Scan, User, utcnow
from app.services import observability
from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session, selectinload

router = APIRouter(prefix="/findings", tags=["findings"],
                   dependencies=[Depends(deps.require_csrf)])


def _own_finding(db: Session, user: User, finding_id: str) -> Finding:
    try:
        fid = uuid_lib.UUID(finding_id)
    except (ValueError, TypeError):
        raise HTTPException(status_code=404, detail={"code": "NOT_FOUND",
                                                     "message": "Finding not found."})
    finding = (
        db.query(Finding).options(selectinload(Finding.evidence_items))
        .filter(Finding.id == fid).first()
    )
    if finding is None or finding.user_id != user.id:
        raise HTTPException(status_code=404, detail={"code": "NOT_FOUND",
                                                     "message": "Finding not found."})
    return finding


@router.get("")
def list_findings(
    db: Session = Depends(get_db),
    user: User = Depends(deps.get_current_user),
    severity: str | None = None,
    status: str | None = None,
    asset_id: str | None = None,
    vuln: str | None = None,
    limit: int = 200,
):
    q = db.query(Finding).filter(Finding.user_id == user.id)
    if severity:
        q = q.filter(Finding.severity.in_(severity.split(",")))
    if status:
        q = q.filter(Finding.status.in_(status.split(",")))
    if vuln:
        q = q.filter(Finding.vulnerability_id == vuln)
    if asset_id:
        try:
            q = q.filter(Finding.asset_id == uuid_lib.UUID(asset_id))
        except ValueError:
            return {"findings": []}
    findings = q.order_by(Finding.last_seen.desc()).limit(min(limit, 500)).all()
    out = []
    for f in findings:
        asset = db.get(Asset, f.asset_id)
        data = f.to_json()
        data["asset_name"] = asset.name if asset else None
        data["asset_url"] = asset.normalized_url if asset else None
        out.append(data)
    return {"findings": out}


@router.get("/{finding_id}")
def get_finding(finding_id: str, db: Session = Depends(get_db),
                user: User = Depends(deps.get_current_user)):
    finding = _own_finding(db, user, finding_id)
    asset = db.get(Asset, finding.asset_id)
    data = finding.to_json()
    data["asset_name"] = asset.name if asset else None
    data["asset_url"] = asset.normalized_url if asset else None
    data["evidence"] = [
        {
            "id": str(e.id),
            "type": e.evidence_type,
            "name": e.name,
            "value": e.value,
            "source": e.source,
            "confidence": e.confidence,
            "collected_at": e.collected_at.isoformat() if e.collected_at else None,
        }
        for e in finding.evidence_items
    ]
    data["disclosures"] = [
        {
            "id": str(d.id),
            "status": d.status,
            "delivery_status": d.delivery_status,
            "recipient_email": d.recipient_email,
            "created_at": d.created_at.isoformat(),
            "sent_at": d.sent_at.isoformat() if d.sent_at else None,
        }
        for d in finding.disclosures
    ]
    return data


@router.post("/{finding_id}/rescan", status_code=202)
def rescan_finding(finding_id: str, request: Request, db: Session = Depends(get_db),
                   user: User = Depends(deps.get_current_user)):
    enforce(request, action="scan-start", max_requests=10, window_seconds=300,
            user_scope=str(user.id))
    finding = _own_finding(db, user, finding_id)
    asset = db.get(Asset, finding.asset_id)
    deps.require_authorized_asset(asset)
    if not asset:
        raise HTTPException(status_code=404, detail={"code": "NOT_FOUND",
                                                     "message": "Asset not found."})
    scan = Scan(asset_id=asset.id, user_id=user.id, status="QUEUED")
    db.add(scan)
    db.flush()
    observability.audit(user_id=user.id, asset_id=asset.id, action="SCAN_QUEUED",
                        resource_type="scan", resource_id=scan.id,
                        detail={"via": "finding_rescan",
                                "asset_url": asset.normalized_url})
    db.commit()
    from app.workers.tasks import scan_asset
    scan_asset.apply_async(args=[str(scan.id)], task_id=str(scan.id))
    return {"scan_id": str(scan.id), "status": "QUEUED"}


@router.post("/{finding_id}/verify-fix", status_code=202)
def verify_fix(finding_id: str, request: Request, db: Session = Depends(get_db),
               user: User = Depends(deps.get_current_user)):
    """Queues a fresh scan for remediation verification."""
    enforce(request, action="scan-start", max_requests=10, window_seconds=300,
            user_scope=str(user.id))
    finding = _own_finding(db, user, finding_id)
    asset = db.get(Asset, finding.asset_id)
    deps.require_authorized_asset(asset)
    scan = Scan(asset_id=asset.id, user_id=user.id, status="QUEUED",
                scanner_version=None)
    db.add(scan)
    db.flush()
    observability.audit(user_id=user.id, asset_id=asset.id, action="VERIFY_FIX_QUEUED",
                        resource_type="scan", resource_id=scan.id,
                        detail={"finding_id": str(finding.id)})
    db.commit()
    from app.workers.tasks import scan_asset
    scan_asset.apply_async(args=[str(scan.id)], task_id=str(scan.id))
    return {"scan_id": str(scan.id), "status": "QUEUED", "verify_fix": True}


@router.post("/{finding_id}/close")
def close_finding(finding_id: str, db: Session = Depends(get_db),
                  user: User = Depends(deps.get_current_user)):
    finding = _own_finding(db, user, finding_id)
    if finding.state not in ("PATCHED",):
        raise HTTPException(status_code=409, detail={
            "code": "CANNOT_CLOSE",
            "message": "Only PATCHED findings can be closed. Run Verify Fix first.",
        })
    finding.status = "RESOLVED"
    finding.resolved_at = utcnow()
    observability.audit(user_id=user.id, asset_id=finding.asset_id, action="FINDING_CLOSED",
                        resource_type="finding", resource_id=finding.id,
                        detail={"vulnerability_id": finding.vulnerability_id})
    observability.notify(user_id=user.id, type_="finding",
                         title=f"Finding closed: {finding.title}",
                         message=f"{finding.vulnerability_id} marked resolved.",
                         db=db)
    db.commit()
    return finding.to_json()
