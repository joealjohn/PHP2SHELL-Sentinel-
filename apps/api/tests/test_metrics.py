from __future__ import annotations

from app.core.db import SessionFactory
from app.services.scan_exec import execute_scan


def _execute_scan_sync(scan_id):
    db = SessionFactory()
    try:
        return execute_scan(db, scan_id)
    finally:
        db.close()


class TestMetricsSummary:
    def test_recent_assets_carry_scan_state(self, api_user_a, asset_a):
        r = api_user_a.post(f"/api/assets/{asset_a['id']}/scan")
        assert r.status_code == 202, r.text
        result = _execute_scan_sync(r.json()["scan_id"])
        assert result["status"] == "COMPLETED", result

        m = api_user_a.get("/api/metrics/summary").json()
        row = next(a for a in m["recent_assets"] if a["id"] == asset_a["id"])
        assert row["last_scan_status"] == "COMPLETED"
        assert row["last_scan_at"] is not None
        assert row["open_findings"] == 1
        assert m["assets"] >= 1
        assert m["open_findings"] >= 1

    def test_recent_assets_inconclusive_flags(self, api_user_a, asset_a):
        r = api_user_a.post(f"/api/assets/{asset_a['id']}/scan")
        assert r.status_code == 202, r.text
        result = _execute_scan_sync(r.json()["scan_id"])
        assert result["status"] == "COMPLETED", result

        from app.core.db import SessionFactory
        from app.models import Scan
        db = SessionFactory()
        try:
            scan = db.query(Scan).order_by(
                Scan.created_at.desc()).first()
            summary = dict(scan.summary or {})
            summary["php"] = {"detected": True, "version": None,
                              "confidence": "LOW", "stack": "WordPress"}
            summary["shielded"] = {"kind": "js_challenge_infinityfree", "shielded": True}
            scan.summary = summary
            db.commit()
        finally:
            db.close()

        m = api_user_a.get("/api/metrics/summary").json()
        row = next(a for a in m["recent_assets"] if a["id"] == asset_a["id"])
        assert row["last_scan_shielded"] is True
        assert row["last_scan_inconclusive"] is True

        # a plain completed scan without php/shield data stays conclusive
        db = SessionFactory()
        try:
            scan = db.query(Scan).order_by(Scan.created_at.desc()).first()
            summary = dict(scan.summary or {})
            summary["shielded"] = None
            summary["php"] = {"detected": True, "version": "8.4.27"}
            scan.summary = summary
            db.commit()
        finally:
            db.close()
        m = api_user_a.get("/api/metrics/summary").json()
        row = next(a for a in m["recent_assets"] if a["id"] == asset_a["id"])
        assert row["last_scan_shielded"] is False
        assert row["last_scan_inconclusive"] is False

    def test_recent_assets_zero_state(self, api_user_a, asset_a):
        m = api_user_a.get("/api/metrics/summary").json()
        row = next(a for a in m["recent_assets"] if a["id"] == asset_a["id"])
        assert row["last_scan_status"] is None
        assert row["last_scan_at"] is None
        assert row["open_findings"] == 0
