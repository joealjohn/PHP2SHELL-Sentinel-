from __future__ import annotations

from datetime import timedelta

import pytest
from app.core.db import SessionFactory
from app.models import Scan, User, utcnow
from app.workers.tasks import fail_stuck_scans


@pytest.fixture(autouse=True)
def _stale_env(monkeypatch):
    monkeypatch.setenv("STUCK_SCANS_STALE_SECONDS", "600")


def _user_id(db, email: str) -> str:
    return (db.query(User).filter(User.email == email).first()).id


def _make_scan(user_id, asset_id, status, age_seconds):
    db = SessionFactory()
    try:
        old = utcnow() - timedelta(seconds=age_seconds)
        scan = Scan(asset_id=asset_id, user_id=user_id, status=status,
                    created_at=old)
        if status != "QUEUED":
            scan.started_at = old
        db.add(scan)
        db.commit()
        sid = str(scan.id)
    finally:
        db.close()
    return sid


def _get_scan(scan_id):
    db = SessionFactory()
    try:
        s = db.get(Scan, scan_id)
        return {"status": s.status, "error_code": s.error_code,
                "completed_at": s.completed_at,
                "duration_seconds": s.duration_seconds}
    finally:
        db.close()


class TestFailStuckScans:
    def test_queued_scan_going_stale_is_failed(self, api_user_a, asset_a):
        db = SessionFactory()
        try:
            uid = str(_user_id(db, api_user_a.email))
        finally:
            db.close()
        scan_id = _make_scan(uid, asset_a["id"], "QUEUED", 3600)
        result = fail_stuck_scans()
        assert result >= 1
        row = _get_scan(scan_id)
        assert row["status"] == "FAILED"
        assert row["error_code"] == "SCAN_STUCK_QUEUED"
        assert row["completed_at"] is not None
        assert row["duration_seconds"] is None

    def test_running_scan_going_stale_is_failed_with_duration(
            self, api_user_a, asset_a):
        db = SessionFactory()
        try:
            uid = str(_user_id(db, api_user_a.email))
        finally:
            db.close()
        scan_id = _make_scan(uid, asset_a["id"], "SCANNING", 3600)
        result = fail_stuck_scans()
        assert result >= 1
        row = _get_scan(scan_id)
        assert row["status"] == "FAILED"
        assert row["error_code"] == "SCAN_STUCK"
        assert row["completed_at"] is not None
        assert row["duration_seconds"] > 0

    def test_fresh_scan_is_not_touched(self, api_user_a, asset_a):
        db = SessionFactory()
        try:
            uid = str(_user_id(db, api_user_a.email))
        finally:
            db.close()
        scan_id = _make_scan(uid, asset_a["id"], "SCANNING", 10)
        assert fail_stuck_scans() == 0
        assert _get_scan(scan_id)["status"] == "SCANNING"

    def test_analyzing_scan_is_also_swept(self, api_user_a, asset_a):
        db = SessionFactory()
        try:
            uid = str(_user_id(db, api_user_a.email))
        finally:
            db.close()
        scan_id = _make_scan(uid, asset_a["id"], "ANALYZING", 3600)
        result = fail_stuck_scans()
        assert result >= 1
        row = _get_scan(scan_id)
        assert row["status"] == "FAILED"

    def test_disabled_is_noop(self, api_user_a, asset_a, monkeypatch):
        db = SessionFactory()
        try:
            uid = str(_user_id(db, api_user_a.email))
        finally:
            db.close()
        scan_id = _make_scan(uid, asset_a["id"], "QUEUED", 3600)
        monkeypatch.setenv("STUCK_SCANS_ENABLED", "0")
        assert fail_stuck_scans() == 0
        assert _get_scan(scan_id)["status"] == "QUEUED"
