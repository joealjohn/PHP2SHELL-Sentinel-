from __future__ import annotations

import re
from pathlib import Path
from typing import Any
from uuid import UUID as UUIDT

import jinja2
from jinja2.sandbox import SandboxedEnvironment

from app.core.config import get_settings

TEMPLATES_DIR = Path(__file__).resolve().parent / "templates"

_NO_RCE_NOTE = "No exploitation was performed. No remote code execution payload was executed, and no attempt was made to access, modify, or retrieve sensitive information."


def build_subject(finding: Any, asset: Any) -> str:
    title = re.sub(r"\s*detected\s*$", "", str(finding.title), flags=re.IGNORECASE)
    return (
        f"Security vulnerability notification - {title} detected on "
        f"{asset.host}"
    )


def display_name_for(email: str | None) -> str:
    """Derive a professional sign-off name from the sender's account email.

    joeal.john@example.com  -> "Joeal John"
    joeal_john-admin@…      -> "Joeal John Admin"
    joealjohn290@…          -> "Joealjohn" (best effort; the draft stays
    editable before sending so the sender can adjust the signature).
    """
    if not email:
        return "Sentinel Security Monitoring"
    local = email.split("@", 1)[0]
    parts = [p for p in re.split(r"[._\-+]+", local) if p and not p.isdigit()]
    if len(parts) == 1:
        stripped = re.sub(r"\d+$", "", parts[0])
        parts = [stripped] if stripped else [local]
    words = [p[:1].upper() + p[1:] for p in parts if p]
    return " ".join(words) if words else "Sentinel Security Monitoring"


def build_disclosure_email(
    finding: Any, asset: Any, evidence_items: list[Any],
    sender_email: str | None = None,
) -> str:
    """Compose the human-readable responsible disclosure email body."""
    cves = _cves_of(finding)
    title_cased = str(finding.severity).title() if finding.severity else "Unknown"
    confidence = str(finding.confidence).title() if finding.confidence else "Unknown"
    lines = [
        "Dear Security Team,",
        "",
        (f"I am writing to responsibly report a potential security "
         f"vulnerability identified on {asset.host} during a non-invasive "
         f"security assessment."),
        "",
        f"Vulnerability: {finding.title}",
        f"Severity: {title_cased}",
        f"Confidence: {confidence}",
        f"Affected Host: {asset.host}",
        "",
        "Observed Evidence",
        "",
    ]
    if cves:
        lines += [f"CVE reference: {' / '.join(cves)}", ""]
    if finding.detected_version:
        lines += [f"Software version detected: {finding.detected_version}", ""]
    lines += ["The following indicators were observed on public endpoints:"]
    for e in evidence_items[:6]:
        value = (e.value or "").splitlines()[0][:240]
        lines.append(f"- [{e.evidence_type}] {e.name}: {value}")
    lines += [
        "",
        ("These indicators suggest the host may be affected by this "
         "vulnerability, depending on whether the relevant security fixes "
         "have been backported by the operating-system or vendor package."),
        "",
        "Security Impact",
        "",
        finding.impact or "",
        "",
        "Testing Performed",
        "",
        _NO_RCE_NOTE,
        ("The finding is based solely on non-invasive identification of "
         "exposed software/version information."),
        "",
        "Recommended Remediation",
        "",
        finding.remediation or "",
        "",
        "Relevant references:",
    ]
    refs = finding.references if isinstance(finding.references, list) else []
    for r in refs[:6]:
        lines.append(f"- {r}")
    lines += [
        "",
        ("I am sharing this information in good faith so that the issue can "
         "be investigated and remediated before it can potentially be "
         "abused."),
        "",
        ("Please let me know if you require additional non-invasive technical "
         "details regarding the observation."),
        "",
        "Regards,",
        display_name_for(sender_email),
        "",
        f"Sentinel — authorized non-invasive scan {asset.host}",
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
