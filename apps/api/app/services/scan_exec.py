from __future__ import annotations

import asyncio
import logging
import re as re_mod
from datetime import timedelta

from sqlalchemy.orm import Session

from app.models import (
    Asset,
    Evidence,
    Finding,
    Scan,
    User,
    utcnow,
)

log = logging.getLogger("sentinel.scan")


def _sanitize(text: str | None) -> str | None:
    if not text:
        return text
    return re_mod.sub(r"(?i)(password|token|authorization|cookie)\s*[:=]\s*\S+",
                      r"\1=[REDACTED]", text[:1200])


def _scanner_config():
    from sentinel_scanner.core.config import ScannerConfig

    cfg = ScannerConfig.from_env()
    from sentinel_scanner import __version__ as scanner_version
    return cfg, scanner_version


def _finding_records(report) -> list[dict]:
    findings = []
    for entry in report.findings or []:
        if not entry:
            continue
        if isinstance(entry, dict) and entry.get("entry") is not None:
            e = entry["entry"]
            findings.append({
                "vulnerability_id": e.id,
                "title": entry["title"],
                "severity": entry["severity"],
                "cvss": entry["cvss"],
                "confidence": entry["confidence"].value if hasattr(entry["confidence"], "value") else str(entry["confidence"]),
                "state": entry["state"].value if hasattr(entry["state"], "value") else str(entry["state"]),
                "summary": entry["summary"],
                "impact": entry["impact"],
                "remediation": entry["remediation"],
                "detected_version": entry.get("detected_php_version"),
                "fixed_version": entry.get("fixed_version"),
                "vendor_patch_possible": entry.get("vendor_patch_possible", False),
                "detection_method": "remote_version_comparison",
                "scanner_version": report.scanner_version,
                "references": entry.get("references", []),
                "evidence": entry.get("evidence", []),
            })
    return findings


def execute_scan(db: Session, scan_id: str, celery_task_id: str | None = None) -> dict:
    scan = db.get(Scan, _uuid(scan_id))
    asset = None
    if scan is None:
        return {"error": "scan_not_found", "scan_id": scan_id}
    if scan.status not in ("QUEUED", ):
        return {"error": "scan_not_queued", "scan_id": scan_id, "status": scan.status}

    scan.status = "SCANNING"
    scan.started_at = utcnow()
    scan.celery_task_id = celery_task_id
    asset = db.get(Asset, scan.asset_id)
    user = db.get(User, scan.user_id)
    db.commit()

    try:
        cfg, scanner_version = _scanner_config()
        scan.scanner_version = scanner_version

        from sentinel_scanner.evidence.scan import ScanRunner

        runner = ScanRunner(asset.normalized_url, config=cfg)
        report = asyncio.run(runner.run())

        scan.status = "ANALYZING"
        db.commit()

        if not report.reachable:
            scan.status = "FAILED"
            scan.error_code = getattr(report, "error_code", None) or "UNREACHABLE"
            scan.error = _sanitize(report.error) or "Target unreachable"
            scan.completed_at = utcnow()
            scan.duration_seconds = _duration(scan)
            db.commit()
            _notify_failed(db, user, asset, scan)
            db.commit()
            return {"scan_id": str(scan.id), "status": "FAILED",
                    "error": scan.error}

        tech_summary = [
            {"technology": t.get("technology"),
             "confidence": t.get("confidence"),
             "version": t.get("version")}
            for t in (report.technologies or [])
        ]
        shield_payload = None
        if getattr(report, "shielded", None) is not None \
                and getattr(report.shielded, "shielded", False):
            shield_payload = {
                "shielded": True,
                "kind": report.shielded.kind,
                "signals": [e.raw() for e in report.shielded.evidence],
                "note": (
                    "Target served a bot-challenge/JS-only page instead of "
                    "real content; PHP exposure could not be assessed. "
                    "Treat the result as inconclusive, not as a clean bill "
                    "of health. Sentinel observes challenges and never "
                    "attempts to bypass them."
                ),
            }
        php_block = {
            "detected": bool(report.php and report.php.detected),
            "version": report.php.version if report.php else None,
            "confidence": report.php.confidence.value if report.php and hasattr(
                report.php.confidence, "value") else None,
            "phpinfo_exposed": bool(report.php and report.php.phpinfo_exposed),
            "stack": report.app_stack or getattr(report.php, "stack", None)
            if report.php else None,
        }
        scan.summary = {
            "final_url": report.final_url,
            "status_code": report.status_code,
            "requests_made": report.requests_made,
            "duration_ms": report.duration_ms,
            "technologies": tech_summary,
            "php": php_block,
            "app_stack": report.app_stack,
            "shielded": shield_payload,
            "scanner_version": report.scanner_version,
        }

        records = _finding_records(report)
        created_or_updated = _apply_findings(db, asset, scan, user, records)
        current_php_version = report.php.version if (
            report.php and report.php.version) else None
        _reconcile_missing(db, asset, scan, records, current_php_version)

        scan.status = "COMPLETED"
        scan.completed_at = utcnow()
        scan.duration_seconds = _duration(scan)
        asset.last_scan_at = utcnow()
        if asset.monitoring_enabled:
            asset.next_scan_at = utcnow() + timedelta(
                seconds=asset.scan_interval_seconds)
        else:
            asset.next_scan_at = None
        db.commit()

        from app.services import observability
        observability.audit(user_id=scan.user_id, asset_id=asset.id, action="SCAN_COMPLETED",
                            resource_type="scan", resource_id=scan.id,
                            detail={"technologies": tech_summary[:6],
                                    "findings": len(records)})
        db.commit()
        return {"scan_id": str(scan.id), "status": "COMPLETED",
                "findings": created_or_updated}
    except Exception as exc:
        log.exception("scan execution failed")
        scan.status = "FAILED"
        from sentinel_scanner.core.errors import ScanTargetError
        if isinstance(exc, ScanTargetError):
            scan.error_code = exc.code
            scan.error = _sanitize(exc.message)
        else:
            scan.error_code = "SCAN_ERROR"
            scan.error = _sanitize(f"type={type(exc).__name__} detail={exc}")
        scan.completed_at = utcnow()
        scan.duration_seconds = _duration(scan)
        db.commit()
        _notify_failed(db, user, asset, scan)
        db.commit()
        return {"scan_id": str(scan.id), "status": "FAILED", "error": scan.error}


def _duration(scan: Scan) -> float | None:
    if scan.started_at and scan.completed_at:
        return max(0.0, (scan.completed_at - scan.started_at).total_seconds())
    return None


def _apply_findings(db: Session, asset: Asset, scan: Scan, user,
                    records: list[dict]) -> int:
    count = 0
    for rec in records:
        vuln_id = rec["vulnerability_id"]
        state = rec["state"]
        existing = (db.query(Finding)
                    .filter(Finding.asset_id == asset.id,
                            Finding.vulnerability_id == vuln_id)
                    .order_by(Finding.last_seen.desc())
                    .first())
        is_new = existing is None or existing.status == "RESOLVED"
        if existing is None:
            existing = Finding(
                asset_id=asset.id, user_id=asset.user_id, scan_id=scan.id,
                vulnerability_id=vuln_id, status="OPEN",
                first_seen=utcnow(),
            )
            db.add(existing)
        else:
            if existing.status == "RESOLVED":
                # resurrect: keep history, start a fresh lifecycle for the same vuln
                is_new = True
        existing.scan_id = scan.id
        existing.title = rec["title"]
        existing.severity = rec["severity"]
        existing.cvss = rec["cvss"]
        existing.confidence = rec["confidence"]
        existing.state = state
        existing.summary = rec["summary"]
        existing.impact = rec["impact"]
        existing.remediation = rec["remediation"]
        existing.detected_version = rec["detected_version"]
        existing.fixed_version = rec["fixed_version"]
        existing.vendor_patch_possible = rec["vendor_patch_possible"]
        existing.detection_method = rec["detection_method"]
        existing.scanner_version = rec["scanner_version"]
        existing.references = rec["references"]
        existing.last_seen = utcnow()
        existing.status = "OPEN"
        existing.resolved_at = None
        db.flush()

        db.query(Evidence).filter(Evidence.finding_id == existing.id).delete()
        for ev in rec["evidence"]:
            db.add(Evidence(
                finding_id=existing.id,
                evidence_type=ev.get("type", ""),
                name=ev.get("name", ""),
                value=ev.get("value", ""),
                source=ev.get("source"),
                confidence=ev.get("confidence"),
            ))

        from app.services import observability
        if is_new:
            existing.first_seen = utcnow()
            observability.notify(
                user_id=asset.user_id, type_="finding",
                title=f"New {rec['severity']} finding — {rec['title']}",
                message=f"{vuln_id} detected on {asset.host}".strip(),
                data={"finding_id": str(existing.id), "asset_id": str(asset.id),
                      "severity": rec["severity"]},
            )
        observability.audit(user_id=asset.user_id, asset_id=asset.id,
                            action="FINDING_OPENED" if is_new else "FINDING_UPDATED",
                            resource_type="finding", resource_id=existing.id,
                            detail={"vulnerability_id": vuln_id,
                                    "state": state, "confidence": rec["confidence"]})
        count += 1
    db.flush()
    return count


def _reconcile_missing(db: Session, asset: Asset, scan: Scan, records: list[dict],
                       current_php_version: str | None) -> None:
    """Reconcile findings from earlier scans that did not recur in this scan.

    PATCHED is set only when this scan's evidence proves remediation (its fresh
    PHP evidence is at or above the fixed release). Unreachable targets never
    consume findings.
    """
    detected_ids = {r["vulnerability_id"] for r in records}
    open_findings = (db.query(Finding)
                     .filter(Finding.asset_id == asset.id,
                             Finding.resolved_at.is_(None)).all())
    for finding in open_findings:
        if finding.vulnerability_id in detected_ids:
            continue
        _maybe_mark_patched(db, finding, asset, current_php_version)


def _maybe_mark_patched(db: Session, finding: Finding, asset: Asset,
                        fresh_version: str | None) -> bool:
    if finding.resolved_at is not None and finding.status == "RESOLVED" \
            and finding.state == "PATCHED":
        return True
    check_version = fresh_version or finding.detected_version
    if not finding.fixed_version or not check_version:
        return False
    if not _version_at_fixed(check_version, finding.fixed_version):
        return False
    _mark_patched(db, finding, asset)
    return True


def _version_at_fixed(detected: str, fixed: str) -> bool:
    from sentinel_shared.versioning import compare_versions
    return compare_versions(detected, fixed) >= 0


def _mark_patched(db: Session, finding: Finding, asset: Asset) -> None:
    if finding.status == "RESOLVED" and finding.state == "PATCHED":
        return
    already_patched = finding.state == "PATCHED"
    before_state = finding.state
    finding.state = "PATCHED"
    finding.last_seen = utcnow()
    from app.services import observability
    if not already_patched and before_state != "PATCHED":
        observability.notify(
            user_id=asset.user_id, type_="remediation",
            title=f"Remediation verified — {finding.title}",
            message=(f"Vulnerability {finding.vulnerability_id} is no longer detected; "
                     f"further verified with a rescan."),
            data={"finding_id": str(finding.id), "asset_id": str(asset.id)},
        )
        observability.audit(user_id=asset.user_id, asset_id=asset.id,
                            action="FINDING_PATCHED", resource_type="finding",
                            resource_id=finding.id,
                            detail={"vulnerability_id": finding.vulnerability_id})


def _notify_failed(db: Session, user, asset, scan: Scan) -> None:
    from app.services import observability
    observability.notify(
        user_id=scan.user_id, type_="scan",
        title=f"Scan failed — {asset.name}"
        if asset else "Scan failed",
        message=f"{(scan.error_code or 'ERROR')}: {scan.error}"[:400],
        data={"scan_id": str(scan.id), "asset_id": str(asset.id) if asset else None},
    )


def _sanitize(text: str | None) -> str | None:
    import re
    if not text:
        return text
    return re.sub(r"(?i)(password|token|authorization|cookie)\s*[:=]\s*\S+",
                  r"\1=[REDACTED]", text[:1200])


def _uuid(value: str):
    import uuid
    return uuid.UUID(str(value))
