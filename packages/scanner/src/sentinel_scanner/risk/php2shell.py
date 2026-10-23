from __future__ import annotations

from typing import Any

from sentinel_shared.versioning import compare_versions, parse_version
from sentinel_vulndb import VulnerabilityDatabase, VulnerabilityEntry

from sentinel_scanner.models import (
    Confidence,
    EvidenceItem,
    FindingState,
    PhpDetection,
    VendorMarkers,
)


class Php2ShellAssessor:
    """Safe, remote, non-exploitative PHP2Shell assessment.

    Uses upstream PHP version evidence only. Before flagging a target the
    assessor never executes payloads, never spawns shells and never attempts
    memory corruption. A vendor may have backported the fix onto an older
    build, therefore:
      - a PHP build that reports a version below the fixed release is flagged
        at the strongest state allowed remotely (HIGH_CONFIDENCE), keeping
        CONFIRMED out of reach for version-based evidence alone;
      - if distro markers appear, `vendor_patch_possible` is set so the report
        can phrase the finding with appropriate caution;
      - version evidence is separated from vendor patch evidence: a version
        equal to or above the fixed release is reported as PATCHED for the
        entry.
    """

    def __init__(self, db: VulnerabilityDatabase) -> None:
        self._primary = db.by_id("PHP2SHELL-2026-A")
        self._secondary = db.by_id("PHP2SHELL-2026-B")
        if self._primary is None:
            raise ValueError("PHP2SHELL-2026-A missing from vulnerability database")

    def assess(
        self,
        php: PhpDetection,
        vendor: VendorMarkers,
        asset_url: str,
    ) -> list[dict[str, Any]] | None:
        if not php.detected or self._primary is None:
            return None
        entry = self._primary
        results: list[dict[str, Any]] = []

        branch_version = php.version
        fixed = None
        branch = None
        if branch_version:
            branch = _branch_of(branch_version)
            fixed = entry.fixed_versions.get(branch)

        if branch_version and fixed and compare_versions(branch_version, fixed) >= 0:
            return None

        state = FindingState.UNKNOWN
        confidence = Confidence.LOW

        if branch_version is None:
            state = FindingState.POTENTIAL
            confidence = Confidence.LOW if php.confidence == Confidence.LOW else Confidence.MEDIUM
        else:
            state = FindingState.HIGH_CONFIDENCE if (
                php.confidence == Confidence.HIGH and not vendor.distro_markers
            ) else FindingState.LIKELY_VULNERABLE
            confidence = _clamp_confidence(php.confidence)
            if branch and branch in entry.affected_eol_branches:
                confidence = _downgrade(confidence)
                state = FindingState.LIKELY_VULNERABLE

        evidence: list[EvidenceItem] = list(php.signals)
        if branch_version and fixed:
            evidence.append(EvidenceItem(
                type="version_comparison",
                name="PHP2Shell fixed release comparison",
                value=f"detected={branch_version} < fixed={fixed}",
                source="scanner_risk/php2shell",
                confidence=Confidence.HIGH,
            ))
        vendor_ev = _vendor_evidence(vendor)
        if vendor_ev:
            evidence.append(vendor_ev)
        evidence.append(EvidenceItem(
            type="assessment_notice",
            name="Non-invasive statement",
            value="No remote code execution payload was executed during this assessment.",
            source="scanner_risk/php2shell",
            confidence=Confidence.HIGH,
        ))

        vendor_patch_possible = bool(vendor.distro_markers) if branch_version else False
        cves = list(entry.cves)
        if self._secondary is not None:
            cves.extend(c for c in self._secondary.cves if c not in cves)

        summary = _summary(entry, branch_version, fixed, state, vendor_patch_possible)
        results.append({
            "entry": entry,
            "cves": cves,
            "state": state,
            "confidence": confidence,
            "severity": entry.severity,
            "cvss": entry.cvss,
            "detected_php_version": branch_version,
            "fixed_version": fixed,
            "summary": summary,
            "impact": _impact(),
            "remediation": entry.remediation,
            "references": list(entry.references),
            "evidence": [e.raw() for e in evidence],
            "vendor_patch_possible": vendor_patch_possible,
            "title": "PHP2Shell exposure detected",
            "asset_url": asset_url,
        })
        return results


def _branch_of(version: str) -> str:
    parts = parse_version(version)
    if parts is None:
        return ""
    return f"{parts.major}.{parts.minor}"


def _vendor_evidence(vendor: VendorMarkers) -> EvidenceItem | None:
    if not vendor.server_header and not vendor.distro_markers:
        return None
    parts = []
    if vendor.server_header:
        parts.append(f"Server: {vendor.server_header}")
    if vendor.distro_markers:
        parts.append("Distro markers: " + ", ".join(vendor.distro_markers))
    return EvidenceItem(
        type="vendor_markers",
        name="Vendor/distro markers",
        value=" | ".join(parts),
        source="scanner_risk/php2shell",
        confidence=Confidence.LOW,
    )


def _summary(entry: VulnerabilityEntry, version: str | None, fixed: str | None,
             state: FindingState, vendor_patch_possible: bool) -> str:
    pieces: list[str] = []
    if version:
        pieces.append(f"PHP {version} was identified from the HTTP response")
        if fixed:
            pieces.append(f"The detected upstream version is below the fixed release {fixed}")
    else:
        pieces.append("PHP is present but the version could not be determined remotely")
    if vendor_patch_possible:
        pieces.append(
            "The vendor may have backported the PHP2Shell fix into this build; "
            "verify package changelogs"
        )
    pieces.append("No remote code execution was attempted")
    return ". ".join(pieces) + "."


def _impact() -> str:
    return (
        "Successful exploitation of the PHP2Shell vulnerability class would pre-auth "
        "allow arbitrary command execution on the affected PHP worker. Impact includes "
        "full server compromise, lateral movement and data theft depending on the "
        "hosting configuration."
    )


def _clamp_confidence(c: Confidence) -> Confidence:
    return c


def _downgrade(c: Confidence) -> Confidence:
    return {Confidence.HIGH: Confidence.MEDIUM,
            Confidence.MEDIUM: Confidence.LOW,
            Confidence.LOW: Confidence.LOW}[c]


__all__ = ["Php2ShellAssessor"]
