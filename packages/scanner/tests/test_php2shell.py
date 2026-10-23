import pytest
from sentinel_scanner.detectors.php import (
    PhpSignal,
    _select_version,
    _signal_from_phpinfo,
    detect_php,
    extract_vendor_markers,
)
from sentinel_scanner.http.client import FetchOutcome
from sentinel_scanner.models import Confidence, FetchResult, FindingState
from sentinel_scanner.risk.php2shell import Php2ShellAssessor
from sentinel_vulndb import load_default

DB = load_default(reload=True)


def _outcome(url="http://t.example.com/", status=200, headers=None, body=""):
    result = FetchResult(
        url=url, final_url=url, status_code=status, headers=headers or {},
        body_text=body, body_len=len(body), content_type="text/html",
    )
    return FetchOutcome(ok=True, status_code=status, result=result)


class TestPhpDetection:
    def test_x_powered_by_high(self):
        o = _outcome(headers={"X-Powered-By": "PHP/8.4.26"})
        det = detect_php(o)
        assert det.detected and det.version == "8.4.26"
        assert det.confidence == Confidence.HIGH
        assert det.version_source == "X-Powered-By"

    def test_server_header_variant(self):
        o = _outcome(headers={"Server": "Apache/2.4.62 (Unix) PHP/8.2.27"})
        det = detect_php(o)
        assert det.detected and det.version == "8.2.27"

    def test_phpinfo_page(self):
        home = _outcome(headers={})
        info = _outcome(
            url="http://t.example.com/phpinfo.php",
            body="<html><body>PHP Version 8.3.13 more",
        )
        det = detect_php(home, info)
        assert det.version == "8.3.13" and det.phpinfo_exposed

    def test_phpsessid_no_version(self):
        o = _outcome(headers={"Set-Cookie": "PHPSESSID=abc123; Path=/"})
        det = detect_php(o)
        assert det.detected and det.version is None
        assert det.confidence == Confidence.MEDIUM

    def test_no_php(self):
        det = detect_php(_outcome(headers={"Server": "nginx/1.24"}, body="<html>hi"))
        assert not det.detected

    def test_prefers_high_confidence_version(self):
        home = _outcome(headers={"X-Powered-By": "PHP/8.4.26"})
        info = _outcome(url="i", body="PHP Version 8.4.26again")
        det = detect_php(home, info)
        assert det.version == "8.4.26"


def test_phpinfo_title_only():
    info = _outcome(body="<title>phpinfo()</title>")
    sig = _signal_from_phpinfo(info.result)
    assert sig is not None and sig.version is None


def test_version_selection_prefers_carriers():
    sigs = [
        PhpSignal("Set-Cookie PHPSESSID", "response_cookie", "PHPSESSID", Confidence.MEDIUM)
    ]
    sel = _select_version(sigs)
    assert sel.version is None


class TestVendorMarkers:
    def test_distro_marker(self):
        o = _outcome(headers={"Server": "Apache/2.4 (Ubuntu) PHP/8.2.27"})
        m = extract_vendor_markers(o.result)
        assert "Ubuntu" in m.distro_markers

    def test_no_marker(self):
        m = extract_vendor_markers(_outcome(headers={"Server": "nginx"}).result)
        assert not m.distro_markers


class TestPhp2ShellAssessor:
    def setup_method(self):
        self.assessor = Php2ShellAssessor(DB)

    def _detect(self, version=None, conf=Confidence.HIGH):
        from sentinel_scanner.models import PhpDetection
        return PhpDetection(detected=True, version=version, confidence=conf,
                            signals=[], version_source="X-Powered-By" if version else "")

    def test_vulnerable_with_hard_version(self):
        det = self._detect("8.4.26")
        vendor = extract_vendor_markers(_outcome(headers={"Server": "Apache"}).result)
        results = self.assessor.assess(det, vendor, "http://example.com")
        assert results
        r = results[0]
        assert r["state"] == FindingState.HIGH_CONFIDENCE
        assert r["severity"] == "CRITICAL"
        assert r["fixed_version"] == "8.4.27"
        assert "CVE-2026-109618" in r["cves"]
        evidence_types = [e["type"] for e in r["evidence"]]
        assert "version_comparison" in evidence_types

    def test_vulnerable_with_vendor_distro_marker_is_likely(self):
        det = self._detect("8.2.27")
        vendor = extract_vendor_markers(
            _outcome(headers={"Server": "Apache (Ubuntu)"}).result)
        results = self.assessor.assess(det, vendor, "")
        assert results[0]["state"] == FindingState.LIKELY_VULNERABLE
        assert results[0]["vendor_patch_possible"]

    def test_patched_not_flagged(self):
        det = self._detect("8.4.27")
        assert self.assessor.assess(det, extract_vendor_markers(None), "") is None

    def test_unmentioned_branch_flagged_likely(self):
        det = self._detect("8.1.30")
        results = self.assessor.assess(det, extract_vendor_markers(None), "")
        assert results[0]["state"] == FindingState.LIKELY_VULNERABLE
        assert [e["confidence"] for e in results[0]["evidence"] if e["type"] == "version_comparison"] == []

    def test_no_version_yet_php_detected(self):
        det = self._detect(None, conf=Confidence.MEDIUM)
        results = self.assessor.assess(det, extract_vendor_markers(None), "")
        assert results[0]["state"] == FindingState.POTENTIAL

    def test_version_string_semantics(self):
        det_low = self._detect("8.4.9")
        det_high = self._detect("8.4.27")
        vendor = extract_vendor_markers(None)
        low = self.assessor.assess(det_low, vendor, "")
        high = self.assessor.assess(det_high, vendor, "")
        assert low and not high

    def test_no_rce_in_summary(self):
        det = self._detect("8.4.26")
        results = self.assessor.assess(det, extract_vendor_markers(None), "")
        assert any("8.4.27" in e["value"] for e in results[0]["evidence"]
                   if e["type"] == "version_comparison")


class TestScanRunnerUnit:
    def test_unsupported_target_errors(self):
        import asyncio

        from sentinel_scanner.core.errors import ScanTargetError
        from sentinel_scanner.evidence.scan import ScanRunner

        async def go():
            return await ScanRunner("http://127.0.0.1/").run()

        with pytest.raises(ScanTargetError):
            asyncio.run(go())

    def test_normalize_in_runner(self):
        from sentinel_scanner.evidence.scan import ScanRunner
        r = ScanRunner("example.com")
        assert r.url == "https://example.com/"
