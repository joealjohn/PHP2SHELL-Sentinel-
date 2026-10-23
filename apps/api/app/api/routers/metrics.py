from __future__ import annotations

from datetime import UTC, datetime, timedelta

from app.api import deps
from app.core.db import get_db
from app.models import Asset, Disclosure, Finding, Scan
from fastapi import APIRouter, Depends
from sqlalchemy import func
from sqlalchemy.orm import Session

router = APIRouter(prefix="/metrics", tags=["metrics"])


@router.get("/summary")
def summary(db: Session = Depends(get_db), user=Depends(deps.get_current_user)):
    assets_total = db.query(func.count(Asset.id)).filter(Asset.user_id == user.id).scalar()
    q = db.query(Finding).filter(Finding.user_id == user.id)
    open_findings = q.filter(
        Finding.status.notin_(["RESOLVED"]), Finding.state.notin_(["PATCHED"])).all()
    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in open_findings:
        severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1
    resolved = db.query(func.count(Finding.id)).filter(
        Finding.user_id == user.id, Finding.resolved_at.isnot(None)).scalar()

    now = datetime.now(UTC)
    scans_q = db.query(Scan).filter(
        Scan.user_id == user.id, Scan.created_at >= now - timedelta(days=14))
    scan_trend: list[dict] = []
    findings_trend: list[dict] = []
    for i in range(13, -1, -1):
        day_start = (now - timedelta(days=i)).replace(hour=0, minute=0, second=0, microsecond=0)
        day_end = day_start + timedelta(days=1)
        scan_trend.append({
            "date": day_start.date().isoformat(),
            "count": scans_q.filter(Scan.created_at >= day_start,
                                    Scan.created_at < day_end).count(),
        })
        findings_trend.append({
            "date": day_start.date().isoformat(),
            "count": (db.query(func.count(Finding.id))
                      .filter(Finding.user_id == user.id,
                              Finding.first_seen >= day_start,
                              Finding.first_seen < day_end).scalar()),
        })
    recent_scans = db.query(Scan).filter(Scan.user_id == user.id)\
        .order_by(Scan.created_at.desc()).limit(5)
    recent_findings = db.query(Finding).filter(Finding.user_id == user.id)\
        .order_by(Finding.last_seen.desc()).limit(5)
    recent_disclosures = db.query(Disclosure).filter(Disclosure.user_id == user.id)\
        .order_by(Disclosure.created_at.desc()).limit(5)
    assets_list = db.query(Asset).filter(Asset.user_id == user.id)\
        .order_by(Asset.created_at.desc()).limit(5)
    findings_with_asset = []
    for f in recent_findings:
        asset = db.get(Asset, f.asset_id)
        data = f.to_json()
        data["asset_name"] = asset.name if asset else None
        findings_with_asset.append(data)
    recent_assets_out = []
    for a in assets_list:
        data = a.to_json()
        data["open_findings"] = (
            db.query(func.count(Finding.id))
            .filter(Finding.asset_id == a.id,
                    Finding.status.notin_(["RESOLVED"]),
                    Finding.state.notin_(["NOT_DETECTED", "PATCHED"]))
            .scalar()
        )
        last = (
            db.query(Scan).filter(Scan.asset_id == a.id,
                                  Scan.status.in_(["COMPLETED", "FAILED"]))
            .order_by(Scan.created_at.desc()).first()
        )
        data["last_scan_status"] = last.status if last else None
        recent_assets_out.append(data)
    return {
        "assets": assets_total,
        "open_findings": len(open_findings),
        "severity": severity_counts,
        "resolved_findings": resolved,
        "scan_trend": scan_trend,
        "findings_trend": findings_trend,
        "recent_scans": [s.to_json() for s in recent_scans],
        "recent_findings": findings_with_asset,
        "recent_disclosures": [d.to_json() for d in recent_disclosures],
        "recent_assets": recent_assets_out,
    }
