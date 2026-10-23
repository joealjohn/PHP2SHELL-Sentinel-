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

    def test_recent_assets_zero_state(self, api_user_a, asset_a):
        m = api_user_a.get("/api/metrics/summary").json()
        row = next(a for a in m["recent_assets"] if a["id"] == asset_a["id"])
        assert row["last_scan_status"] is None
        assert row["last_scan_at"] is None
        assert row["open_findings"] == 0
