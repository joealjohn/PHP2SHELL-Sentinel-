from __future__ import annotations

from pathlib import Path
from typing import Any
from uuid import UUID as UUIDT

import jinja2
from jinja2.sandbox import SandboxedEnvironment

from app.core.config import get_settings

TEMPLATES_DIR = Path(__file__).resolve().parent / "templates"

_NO_RCE_NOTE = "No remote code execution payload was executed during this assessment."


def build_subject(finding: Any, asset: Any) -> str:
    return (
        f"Security vulnerability notification — {finding.title} detected on "
        f"{asset.host}"
    )


def build_disclosure_email(finding: Any, asset: Any, evidence_items: list[Any]) -> str:
    """Compose the human-readable responsible disclosure email body."""
    cves = _cves_of(finding)
    lines = [
        "Hello Security Team,",
        "",
        ("We are contacting you regarding a potential security vulnerability "
         f"identified on {asset.host}."),
        "",
        "Issue:",
        finding.title,
        "",
        "CVE:",
        " / ".join(cves) if cves else "(identifier not published)",
        "",
        "Severity:",
        finding.severity,
        "",
        "Confidence:",
        finding.confidence,
        "",
    ]
    if finding.detected_version:
        lines += ["Detected PHP version:", finding.detected_version, ""]
    lines += ["Observed evidence:"]
    for e in evidence_items[:6]:
        value = (e.value or "").splitlines()[0][:240]
        lines.append(f"- [{e.evidence_type}] {e.name}: {value}")
    lines += [
        "",
        "Recommended remediation:",
        finding.remediation or "",
        "",
        "Important:",
        "No exploitation was performed. " + _NO_RCE_NOTE,
        "",
        "References:",
    ]
    refs = finding.references if isinstance(finding.references, list) else []
    for r in refs[:5]:
        lines.append(f"- {r}")
    lines += [
        "",
        "Regenerate:",
        "Sentinel Security Monitoring (authorized assessment)",
        "",
        "Regards,",
        "Sentinel Security Monitoring",
    ]
    return "\n".join(lines)


def _cves_of(finding: Any) -> list[str]:
    refs = finding.references if isinstance(finding.references, list) else []
    refs = [r for r in refs if isinstance(r, str) and r.upper().startswith("CVE-")]
    return refs


def _jinja_env() -> SandboxedEnvironment:
    env = SandboxedEnvironment(
        loader=jinja2.FileSystemLoader(str(TEMPLATES_DIR)),
        autoescape=True,
    )
    return env


NO_RCE_NOTE = _NO_RCE_NOTE


class ReportState:
    def not_available(self) -> str:
        return ""

    def machinery(self) -> None:
        return None


def render_report_html(report: dict) -> str:
    env = _jinja_env()
    template = env.get_template("report.html.j2")
    return template.render(**report)


def render_report_json(report: dict) -> dict:
    return report


def smtp_from_default() -> str:
    return get_settings().smtp_from


def build_report(finding: Any, asset: Any, evidence_items: list[Any],
                 scan: Any | None, user: Any | None = None) -> dict:
    refs = finding.references if isinstance(finding.references, list) else []
    return {
        "schema": "SENTINEL-REPORT/1.0",
        "generated_at_utc": _utcnow_iso(),
        "finding": {
            "id": str(finding.id),
            "vulnerability_id": finding.vulnerability_id,
            "cves": _cves_of(finding),
            "title": finding.title,
            "summary": finding.summary,
            "impact": finding.impact,
            "remediation": finding.remediation,
            "severity": finding.severity,
            "cvss": float(finding.cvss) if finding.cvss is not None else None,
            "confidence": finding.confidence,
            "state": finding.state,
            "detected_version": finding.detected_version,
            "fixed_version": finding.fixed_version,
            "vendor_patch_possible": finding.vendor_patch_possible,
            "detection_method": finding.detection_method,
            "scanner_version": finding.scanner_version,
            "first_seen": _iso(finding.first_seen),
            "last_seen": _iso(finding.last_seen),
            "resolved_at": _iso(finding.resolved_at),
            "references": list(refs),
        },
        "target": {
            "asset_id": str(asset.id),
            "name": asset.name,
            "host": asset.host,
            "url": asset.normalized_url,
            "authorization_confirmed": asset.authorization_confirmed,
        },
        "scan": {
            "id": str(scan.id) if scan else None,
            "status": scan.status if scan else None,
            "scanner_version": scan.scanner_version if scan else None,
        },
        "evidence": [
            {
                "type": e.evidence_type,
                "name": e.name,
                "value": e.value,
                "source": e.source,
                "confidence": e.confidence,
            }
            for e in evidence_items
        ],
        "statements": [
            f"Authorization to test {asset.host} was confirmed before scanning.",
            "Remote code execution was not attempted during this assessment.",
        ],
    }


def _iso(value: Any) -> str | None:
    if not value:
        return None
    if getattr(value, "tzinfo", None) is not None:
        return value.isoformat()
    return value.isoformat() + "Z"


def _utcnow_iso() -> str:
    from app.models import utcnow

    return utcnow().isoformat()


def disclosure_duplicate_guard(
    may_resend: bool,
    existing: list[Any],
    finding_id: UUIDT,
    recipient: str,
) -> None:
    """Raise if a disclosure was already sent/recipient; resends need explicit user action."""
    for d in existing:
        if d.recipient_email == recipient and d.status in ("SENT", "DELIVERED"):
            if may_resend:
                continue
            raise DuplicateDisclosure()


class DuplicateDisclosure(Exception):
    pass
