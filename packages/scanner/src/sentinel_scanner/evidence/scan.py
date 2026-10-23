from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from urllib.parse import urljoin

from sentinel_shared.urlguard import TargetValidationError, assert_url_scannable
from sentinel_vulndb import VulnerabilityDatabase, load_default

from sentinel_scanner import __version__
from sentinel_scanner.core.config import ScannerConfig
from sentinel_scanner.core.errors import ScanTargetError
from sentinel_scanner.detectors.php import detect_php, extract_vendor_markers
from sentinel_scanner.fingerprint.technologies import run_technology_fingerprinting
from sentinel_scanner.http.client import FetchOutcome, SentinelHttpClient
from sentinel_scanner.models import PhpDetection
from sentinel_scanner.risk.php2shell import Php2ShellAssessor

PHPINFO_CANDIDATES = ("/phpinfo.php", "/info.php")


@dataclass
class ScanReport:
    asset_url: str
    final_url: str = ""
    reachable: bool = False
    status_code: int = 0
    error: str = ""
    error_code: str = ""
    requests_made: int = 0
    duration_ms: int = 0
    technologies: list[dict] = field(default_factory=list)
    php: PhpDetection | None = None
    findings: list[dict] = field(default_factory=list)
    scanner_version: str = __version__


def technologies_to_entries(outcome: FetchOutcome) -> list[dict]:
    detections = run_technology_fingerprinting(outcome)
    return [
        {
            "technology": t.technology,
            "detected": t.detected,
            "confidence": t.confidence.value,
            "version": t.version,
            "evidence": [e.raw() for e in t.evidence],
        }
        for t in detections
    ]


class ScanRunner:
    """Executes one authorized, non-destructive assessment of one asset.

    Steps: URL validation -> DNS/SSRF validation -> safe HTTP collection ->
    technology fingerprinting -> PHP detection -> PHP2Shell assessment.
    The request budget is tiny by design (home page + two phpinfo indicator
    probes), so the scanner never resembles a crawl or brute-force sweep.
    """

    def __init__(self, url: str, config: ScannerConfig | None = None,
                 db: VulnerabilityDatabase | None = None) -> None:
        self.config = config or ScannerConfig.from_env()
        try:
            normalized, _ = assert_url_scannable(
                url, allow_private=self.config.allow_private_targets)
        except TargetValidationError as exc:
            raise ScanTargetError(exc.code, exc.message) from exc
        self.url = normalized
        self._db = db or load_default()

    async def run(self) -> ScanReport:
        started = time.monotonic()
        report = ScanReport(asset_url=self.url)
        assessor = Php2ShellAssessor(self._db)

        async with SentinelHttpClient(self.config) as client:
            try:
                home = await client.get(self.url, follow_redirects=True)
            except ScanTargetError as exc:
                report.error_code, report.error = exc.code, exc.message
                return _finish(report, started)
            report.requests_made = client.requests_made

            if not home.ok or home.result is None:
                report.error_code = home.error_code
                report.error = home.error
                return _finish(report, started)

            result = home.result
            report.reachable = True
            report.final_url = result.final_url
            report.status_code = result.status_code
            report.technologies = technologies_to_entries(home)

            phpinfo = await self._probe_phpinfo(client, result.final_url)
            report.requests_made = client.requests_made

            report.php = detect_php(home, phpinfo)
            vendor = extract_vendor_markers(result)
            results = assessor.assess(report.php, vendor, self.url)
            report.findings = results or []

        return _finish(report, started)

    async def _probe_phpinfo(self, client: SentinelHttpClient,
                             base: str) -> FetchOutcome | None:
        base = base.rstrip("/") + "/"
        outcome: FetchOutcome | None = None
        for path in PHPINFO_CANDIDATES:
            outcome = await client.get(urljoin(base, path.lstrip("/")), follow_redirects=False)
            if outcome.ok and outcome.result is not None and outcome.result.status_code == 200:
                return outcome
        return None


def run_scan_sync(url: str, config: ScannerConfig | None = None,
                  db: VulnerabilityDatabase | None = None) -> ScanReport:
    return asyncio.run(ScanRunner(url, config, db).run())


def _finish(report: ScanReport, started: float) -> ScanReport:
    report.duration_ms = int((time.monotonic() - started) * 1000)
    return report
