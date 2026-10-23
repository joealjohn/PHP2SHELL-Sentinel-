from __future__ import annotations

import logging
from datetime import UTC, datetime

from app.workers.celery_app import celery_app

log = logging.getLogger("sentinel.worker")


@celery_app.task(name="app.workers.tasks.scan_asset", bind=True, max_retries=1,
                 acks_late=True)
def scan_asset(self, scan_id: str) -> dict:
    from app.core.db import SessionFactory
    from app.services.scan_exec import execute_scan

    db = SessionFactory()
    try:
        return execute_scan(db, scan_id, celery_task_id=self.request.id)
    except Exception:
        log.exception("scan_asset failed for scan %s", scan_id)
        raise
    finally:
        db.close()


@celery_app.task(name="app.workers.tasks.discover_contact", bind=True, max_retries=1)
def discover_contact(self, asset_id: str) -> dict:
    from app.core.db import SessionFactory
    from app.services.contact_exec import execute_contact_discovery

    db = SessionFactory()
    try:
        return execute_contact_discovery(db, asset_id)
    finally:
        db.close()


@celery_app.task(name="app.workers.tasks.send_disclosure", bind=True, max_retries=2)
def send_disclosure(self, disclosure_id: str) -> dict:
    from app.core.db import SessionFactory
    from app.services.disclosure_exec import execute_disclosure_send

    db = SessionFactory()
    try:
        return execute_disclosure_send(db, disclosure_id)
    finally:
        db.close()


@celery_app.task(name="app.workers.tasks.send_test_email", bind=True, max_retries=1)
def send_test_email(self, disclosure_id: str) -> dict:
    from app.core.db import SessionFactory
    from app.services.disclosure_exec import execute_test_email

    db = SessionFactory()
    try:
        return execute_test_email(db, disclosure_id)
    finally:
        db.close()


ACTIVE_SCAN_STATUSES = ("QUEUED", "SCANNING", "ANALYZING")


@celery_app.task(name="app.workers.tasks.fail_stuck_scans")
def fail_stuck_scans() -> int:
    """Sweep: fail scans stuck in QUEUED/RUNNING beyond the stale threshold.

    QUEUED scans are judged by created_at (never picked up by a worker);
    SCANNING/ANALYZING scans by started_at (task crashed without acking).
    """
    import os

    from app.core.db import SessionFactory
    from app.models import Scan, utcnow
    from app.services import observability

    if os.getenv("STUCK_SCANS_ENABLED", "1").lower() in ("0", "false", "no"):
        return 0
    try:
        stale_seconds = float(os.getenv("STUCK_SCANS_STALE_SECONDS", "900"))
    except ValueError:
        stale_seconds = 900.0

    db = SessionFactory()
    try:
        now = utcnow()
        stuck = 0
        active = (db.query(Scan)
                  .filter(Scan.status.in_(ACTIVE_SCAN_STATUSES)).all())
        for scan in active:
            ref = scan.started_at if scan.status != "QUEUED" else scan.created_at
            if ref is None:
                continue
            ref = ref if ref.tzinfo else ref.replace(tzinfo=UTC)
            age = now - ref
            if age.total_seconds() < stale_seconds:
                continue
            was_queued = scan.status == "QUEUED"
            scan.status = "FAILED"
            scan.error_code = "SCAN_STUCK_QUEUED" if was_queued else "SCAN_STUCK"
            scan.error = (
                "Scan was queued but never picked up by a worker "
                "and was automatically failed as stale"
            ) if was_queued else (
                "Scan exceeded the maximum runtime and was automatically "
                "failed as stale"
            )
            scan.completed_at = now
            if scan.started_at:
                started = scan.started_at
                started = started if started.tzinfo else \
                    started.replace(tzinfo=UTC)
                scan.duration_seconds = max(
                    0.0, (now - started).total_seconds())
            observability.notify(
                user_id=scan.user_id, type_="scan",
                title="Scan failed (stale)",
                message=str(scan.error),
                data={"scan_id": str(scan.id), "asset_id": str(scan.asset_id)},
            )
            observability.audit(user_id=scan.user_id, asset_id=scan.asset_id,
                                action="SCAN_STALE_FAILED", resource_type="scan",
                                resource_id=scan.id,
                                detail={"error_code": scan.error_code})
            stuck += 1
        db.commit()
        if stuck:
            log.warning("fail_stuck_scans failed %s stale scans", stuck)
        return stuck
    finally:
        db.close()


@celery_app.task(name="app.workers.tasks.schedule_due_scans")
def schedule_due_scans() -> int:
    """Monitoring: enqueue scans for assets whose next_scan_at is due."""
    from app.core.db import SessionFactory
    from app.models import Asset, Scan

    db = SessionFactory()
    try:
        now = datetime.now(UTC)
        assets = (db.query(Asset)
                  .filter(Asset.monitoring_enabled.is_(True),
                          Asset.authorization_confirmed.is_(True))
                  .all())
        queued = 0
        for asset in assets:
            if asset.next_scan_at is None:
                continue
            due = asset.next_scan_at if asset.next_scan_at.tzinfo \
                else asset.next_scan_at.replace(tzinfo=UTC)
            if due <= now:
                running = (db.query(Scan)
                           .filter(Scan.asset_id == asset.id,
                                   Scan.status.in_(["QUEUED", "SCANNING", "ANALYZING"]))
                           .first())
                if running:
                    continue
                scan = Scan(asset_id=asset.id, user_id=asset.user_id, status="QUEUED")
                db.add(scan)
                db.flush()
                scan_asset.apply_async(args=[str(scan.id)], task_id=str(scan.id))
                queued += 1
        db.commit()
        return queued
    finally:
        db.close()
