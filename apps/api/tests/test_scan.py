from __future__ import annotations

import uuid

from app.core.db import SessionFactory
from app.models import Finding
from app.services.scan_exec import execute_scan


def run_scan(api_client, asset):
    r = api_client.post(f"/api/assets/{asset['id']}/scan")
    assert r.status_code == 202, r.text
    scan_id = r.json()["scan_id"]
    result = execute_scan_sync(scan_id)
    assert result["status"] == "COMPLETED", result
    findings = api_client.get(
        f"/api/findings?asset_id={asset['id']}").json()["findings"]
    crit = [x for x in findings if x["severity"] == "CRITICAL"]
    assert crit, findings
    return scan_id, crit[0]


def execute_scan_sync(scan_id):
    db = SessionFactory()
    try:
        return execute_scan(db, scan_id)
    finally:
        db.close()


def find_contacts(asset_id):
    from app.services.contact_exec import execute_contact_discovery
    db = SessionFactory()
    try:
        return execute_contact_discovery(db, asset_id)
    finally:
        db.close()


class TestScanLifecycle:
    def test_scan_creates_finding_with_evidence(self, api_user_a, asset_a):
        scan_id, f = run_scan(api_user_a, asset_a)
        assert f["vulnerability_id"] == "PHP2SHELL-2026-A"
        assert f["severity"] == "CRITICAL"
        assert f["cvss"] == 9.8
        assert f["confidence"] in ("HIGH", "MEDIUM")
        assert f["state"] in ("HIGH_CONFIDENCE", "LIKELY_VULNERABLE")
        assert f["detected_version"] == "8.4.26"
        assert f["fixed_version"] == "8.4.27"
        assert f["remediation"]

        detail = api_user_a.get(f"/api/findings/{f['id']}").json()
        ev = detail["evidence"]
        assert ev
        types = {e["type"] for e in ev}
        assert "version_comparison" in types
        assert "assessment_notice" in types
        rce_notes = [e for e in ev if "was executed" in e["value"].lower()]
        assert any("remote code execution" in e["value"].lower() for e in rce_notes)
        header_ev = [e for e in ev if e["name"].endswith("Powered-By")]
        assert header_ev and "PHP/8.4.26" in header_ev[0]["value"]

    def test_scan_summary_reports_php(self, api_user_a, asset_a):
        run_scan(api_user_a, asset_a)
        scans = api_user_a.get(f"/api/assets/{asset_a['id']}/scans").json()["scans"]
        assert scans
        summary = scans[0]["summary"]
        assert summary["php"]["detected"] is True
        assert summary["php"]["version"] == "8.4.26"

    def test_dedup_same_finding_row(self, api_user_a, asset_a):
        _, f1 = run_scan(api_user_a, asset_a)
        count_before = len(
            [x for x in api_user_a.get(f"/api/findings?asset_id={asset_a['id']}")
             .json()["findings"]])
        _, f2 = run_scan(api_user_a, asset_a)
        count_after = len(
            [x for x in api_user_a.get(f"/api/findings?asset_id={asset_a['id']}")
             .json()["findings"]])
        assert f1["id"] == f2["id"]
        assert count_before == count_after


class TestRemediation:
    def test_verify_fix_ends_patched_and_closable(self, api_user_a, asset_a,
                                                  patched_lab):
        scan_id, f = run_scan(api_user_a, asset_a)
        assert f["detected_version"] == "8.4.26"
        fid = f["id"]
        patched_lab()
        r = api_user_a.post(f"/api/findings/{fid}/verify-fix")
        assert r.status_code == 202, r.text
        verify_scan_id = r.json()["scan_id"]
        result = execute_scan_sync(verify_scan_id)
        assert result["status"] == "COMPLETED"
        db = SessionFactory()
        try:
            row = db.get(Finding, uuid.UUID(fid))
            assert row.state == "PATCHED", row.state
        finally:
            db.close()
        assert api_user_a.post(
            f"/api/findings/{fid}/close").json()["status"] == "RESOLVED"



class TestDisclosureFlow:
    def test_draft_blocked_without_contact(self, api_user_a, asset_a):
        scan_id, f = run_scan(api_user_a, asset_a)
        r = api_user_a.post(f"/api/findings/{f['id']}/disclosure")
        assert r.status_code == 409
        assert r.json()["error"]["code"] == "NO_CONTACT"

    def test_contact_discovery_finds_security_txt(self, api_user_a, asset_a):
        assert api_user_a.post(
            f"/api/assets/{asset_a['id']}/contacts/discover").status_code == 202
        out = find_contacts(asset_a["id"])
        assert out["contacts_found"] >= 1
        contacts = api_user_a.get(
            f"/api/assets/{asset_a['id']}/contacts").json()["contacts"]
        assert contacts
        assert contacts[0]["confidence"] in ("HIGH", "MEDIUM", "LOW")

    def test_full_disclosure_flow(self, api_user_a, asset_a):
        scan_id, f = run_scan(api_user_a, asset_a)
        asset_id = asset_a["id"]
        api_user_a.post(f"/api/assets/{asset_id}/contacts/discover")
        find_contacts(asset_id)
        fid = f["id"]

        draft = api_user_a.post(f"/api/findings/{fid}/disclosure")
        assert draft.status_code == 201, draft.text
        d = draft.json()
        assert d["status"] == "DRAFT"
        assert "Security vulnerability notification" in d["subject"]
        assert "8.4.26" in d["body"]
        assert "No exploitation was performed" in d["body"]

        edit = api_user_a.patch(f"/api/disclosures/{d['id']}", json={
            "subject": d["subject"], "body": d["body"] + "\n\n-- edited",
        })
        assert edit.status_code == 200

        pend = api_user_a.post(f"/api/disclosures/{d['id']}/mark-pending")
        assert pend.status_code == 200
        assert pend.json()["status"] == "PENDING_APPROVAL"

        captured = {}

        class FakeProvider:
            async def send(self, message):
                captured[message.to_email] = message.subject
                return "OK"

        import app.services.email as email_mod
        email_mod._PROVIDER = FakeProvider()
        try:
            test_email_r = api_user_a.post(f"/api/disclosures/{d['id']}/test-email")
            assert test_email_r.status_code == 202, test_email_r.text
            assert message_recipients(captured) == {api_user_a.email}
            approve = api_user_a.post(f"/api/disclosures/{d['id']}/approve")
            assert approve.status_code == 202, approve.text
            assert message_recipients(captured, last=True) == \
                {d["recipient_email"]}
        finally:
            email_mod.reset_provider()

        assert api_user_a.get(f"/api/disclosures/{d['id']}"
                              ).json()["status"] in ("APPROVED", "DELIVERED")

    def test_duplicate_send_blocked(self, api_user_a, asset_a):
        scan_id, f = run_scan(api_user_a, asset_a)
        asset_id = asset_a["id"]
        api_user_a.post(f"/api/assets/{asset_id}/contacts/discover")
        find_contacts(asset_id)
        draft = api_user_a.post(f"/api/findings/{f['id']}/disclosure")
        assert draft.status_code == 201
        did = draft.json()["id"]
        assert api_user_a.post(
            f"/api/disclosures/{did}/mark-pending").status_code == 200

        import app.services.email as email_mod
        email_mod._PROVIDER = _FakeOk()
        try:
            approve = api_user_a.post(f"/api/disclosures/{did}/approve")
            assert approve.status_code == 202
        finally:
            email_mod.reset_provider()

        dup = api_user_a.post(f"/api/findings/{f['id']}/disclosure")
        assert dup.status_code == 409
        assert dup.json()["error"]["code"] == "DUPLICATE_DISCLOSURE"


class _FakeOk:
    async def send(self, message):
        return "OK"


def message_recipients(captured, last: bool = False):
    if last and len(captured) >= 1:
        return {list(captured)[-1]}
    return set(captured)


class TestReports:
    def test_json_and_html(self, api_user_a, asset_a):
        scan_id, f = run_scan(api_user_a, asset_a)
        fid = f["id"]
        j = api_user_a.get(f"/api/reports/findings/{fid}.json")
        assert j.status_code == 200
        report = j.json()
        assert report["schema"].startswith("SENTINEL-REPORT")
        assert report["finding"]["severity"] == "CRITICAL"
        assert any("was not attempted" in s for s in report["statements"])
        assert report["evidence"]
        h = api_user_a.get(f"/api/reports/findings/{fid}.html")
        assert h.status_code == 200
        assert "Vulnerability Report" in h.text


class TestNotificationsAndAudit:
    def test_unread_and_audit(self, api_user_a, asset_a):
        run_scan(api_user_a, asset_a)
        assert api_user_a.get("/api/notifications/unread-count").json()["unread"] >= 1
        events = api_user_a.get("/api/audit").json()["audit_logs"]
        actions = {e["action"] for e in events}
        assert "SCAN_QUEUED" in actions
        assert "FINDING_OPENED" in actions
