from __future__ import annotations

from uuid import UUID as UUIDT

from app.api import deps
from app.core.db import get_db
from app.models import Asset, Evidence, Finding, Scan, User
from app.services.reports import build_report, render_report_html
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse
from sqlalchemy.orm import Session

router = APIRouter(prefix="/reports", tags=["reports"])


def _load(db: Session, user: User, finding_id: str) -> tuple:
    try:
        fid = UUIDT(finding_id)
    except (ValueError, TypeError):
        raise HTTPException(status_code=404, detail={"code": "NOT_FOUND",
                                                     "message": "Finding not found."})
    finding = db.get(Finding, fid)
    if finding is None or finding.user_id != user.id:
        raise HTTPException(status_code=404, detail={"code": "NOT_FOUND",
                                                     "message": "Finding not found."})
    asset = db.get(Asset, finding.asset_id)
    evidence = (db.query(Evidence).filter(Evidence.finding_id == finding.id)
                .order_by(Evidence.collected_at).all())
    scan = db.get(Scan, finding.scan_id) if finding.scan_id else None
    return finding, asset, evidence, scan


@router.get("/findings/{finding_id}.json")
def finding_report_json(finding_id: str, db: Session = Depends(get_db),
                        user: User = Depends(deps.get_current_user)):
    finding, asset, evidence, scan = _load(db, user, finding_id)
    report = build_report(finding, asset, evidence, scan, user)
    return JSONResponse(content=report, headers={
        "Content-Disposition":
            f"attachment; filename=sentinel-report-{finding.vulnerability_id}.json"})


@router.get("/findings/{finding_id}.html", response_class=HTMLResponse)
def finding_report_html(finding_id: str, db: Session = Depends(get_db),
                        user: User = Depends(deps.get_current_user)):
    finding, asset, evidence, scan = _load(db, user, finding_id)
    report = build_report(finding, asset, evidence, scan, user)
    html = render_report_html(report)
    return HTMLResponse(content=html, status_code=200)


@router.get("")
def list_reports(db: Session = Depends(get_db), user: User = Depends(deps.get_current_user)):
    findings = (
        db.query(Finding).filter(Finding.user_id == user.id)
        .order_by(Finding.last_seen.desc()).limit(200).all()
    )
    out = []
    for f in findings:
        asset = db.get(Asset, f.asset_id)
        out.append({
            "finding_id": str(f.id),
            "vulnerability_id": f.vulnerability_id,
            "title": f.title,
            "severity": f.severity,
            "confidence": f.confidence,
            "status": f.status,
            "asset_name": asset.name if asset else None,
            "json_url": f"/reports/findings/{f.id}.json",
            "html_url": f"/reports/findings/{f.id}.html",
        })
    return {"reports": out}
