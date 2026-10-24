from __future__ import annotations

import asyncio
import http.server
import threading

from sentinel_scanner.detectors.app_stack import stack_signals
from sentinel_scanner.detectors.php import detect_php
from sentinel_scanner.evidence.scan import ScanRunner
from sentinel_scanner.http.client import FetchOutcome
from sentinel_scanner.models import Confidence, FetchResult


def _result(headers: dict[str, str] | None = None,
            body: str = "") -> FetchResult:
    return FetchResult(url="https://t/", final_url="https://t/", status_code=200,
                       headers=headers or {}, body_text=body)


def test_php_session_cookie_signal() -> None:
    signals, stack = stack_signals(_result({"Set-Cookie": "PHPSESSID=abc123; HttpOnly"}))
    assert any(s.name == "PHP (session cookie)" for s in signals)
    assert stack is None  # plain PHP - no named framework
    # plumbs through detect_php as PHP present without a version
    outcome = FetchOutcome(ok=True, status_code=200, result=_result(
        {"Set-Cookie": "PHPSESSID=abc123; HttpOnly"}))
    php = detect_php(outcome, extra_signals=signals)
    assert php.detected is True
    assert php.version is None
    assert php.confidence == Confidence.MEDIUM


def test_framework_cookies_name_the_stack() -> None:
    signals, stack = stack_signals(_result({
        "Set-Cookie": "wordpress_logged_in=admin%7C; Secure"}))
    assert stack == "WordPress"
    assert any("WordPress" in s.name for s in signals)

    signals, stack = stack_signals(_result({
        "Set-Cookie": "laravel_session=abc; HttpOnly"}))
    assert stack == "Laravel"


def test_generator_meta_discloses_stack() -> None:
    body = ('<html><head><meta name="generator" '
            'content="WordPress 6.4.2" /></head></html>')
    signals, stack = stack_signals(_result({}, body=body))
    assert stack == "WordPress 6.4.2"
    assert any(s.source == "body_marker" for s in signals)


def test_non_php_generator_is_ignored() -> None:
    body = '<meta name="generator" content="Hugo 0.120" />'
    signals, stack = stack_signals(_result({}, body=body))
    assert signals == []
    assert stack is None


def test_php_header_on_secondary_response() -> None:
    # the 404-probe path: X-Powered-By leaks on error responses even when
    # the application overrides it on the homepage
    signals, _stack = stack_signals(_result(
        {"X-Powered-By": "PHP/7.4.33"}, body="<p>not found</p>"))
    versions = [s for s in signals if s.version == "7.4.33"]
    assert versions, signals
    assert versions[0].confidence == Confidence.HIGH


def test_real_scan_catches_version_via_404_probe() -> None:
    seen = {"hits": 0}

    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, *_a: object) -> None:
            pass

        def do_GET(self) -> None:
            if self.path.startswith("/sentinel-"):
                seen["hits"] += 1
                self.send_response(404)
                self.send_header("X-Powered-By", "PHP/7.4.33")
                self.end_headers()
            elif self.path in ("/phpinfo.php", "/info.php"):
                self.send_response(404)
                self.end_headers()
            else:
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.end_headers()
                self.wfile.write(b"<html><title>plain override site</title>"
                                 b"<div>hello</div></html>")

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    try:
        port = server.server_port
        server_threads = threading.Thread(target=server.serve_forever, daemon=True)
        server_threads.start()
        runner = ScanRunner(
            f"http://127.0.0.1:{port}/",
            config=_scan_config(),
            db=_db_stub(),
        )
        report = asyncio.run(runner.run())
        assert report.reachable is True
        assert seen["hits"] == 1
        assert report.php is not None
        assert report.php.detected is True
        assert report.php.version == "7.4.33"
        assert report.shielded is not None
        assert report.shielded.shielded is False
        assert report.findings, "version 7.4.33 is below every fixed release"
    finally:
        server.shutdown()
        server_threads.join()


def _scan_config():
    from sentinel_scanner.core.config import ScannerConfig
    return ScannerConfig(rate_limit=50.0, allow_private_targets=True)


def _db_stub():
    from sentinel_vulndb import load_default
    return load_default()


def test_scan_report_carries_new_fields() -> None:
    from sentinel_scanner.evidence.scan import ScanReport
    report = ScanReport(asset_url="http://t/")
    assert report.shielded is None and report.app_stack is None
