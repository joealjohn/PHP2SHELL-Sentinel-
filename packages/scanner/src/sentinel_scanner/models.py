from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class Confidence(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


CONFIDENCE_RANK = {Confidence.LOW: 0, Confidence.MEDIUM: 1, Confidence.HIGH: 2}

CONFIDENCE_SCORE = {Confidence.LOW: 0.2, Confidence.MEDIUM: 0.6, Confidence.HIGH: 0.9}

SEVERITY_RANK = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


class FindingState(str, Enum):
    NOT_DETECTED = "NOT_DETECTED"
    POTENTIAL = "POTENTIAL"
    LIKELY_VULNERABLE = "LIKELY_VULNERABLE"
    HIGH_CONFIDENCE = "HIGH_CONFIDENCE"
    CONFIRMED = "CONFIRMED"
    PATCHED = "PATCHED"
    UNKNOWN = "UNKNOWN"


@dataclass
class RedirectHop:
    url: str
    status_code: int
    location: str | None


@dataclass
class FetchResult:
    url: str
    final_url: str
    status_code: int
    headers: dict[str, str]
    body_text: str = ""
    body_len: int = 0
    content_type: str = ""
    elapsed_ms: int = 0
    redirect_chain: list[RedirectHop] = field(default_factory=list)
    set_cookie_count: int = 0

    def header(self, name: str) -> str | None:
        for k, v in self.headers.items():
            if k.lower() == name.lower():
                return v
        return None

    def joined_header(self, name: str) -> str:
        v = self.header(name)
        return v if v is not None else ""


@dataclass
class EvidenceItem:
    type: str
    name: str
    value: str
    source: str
    confidence: Confidence = Confidence.MEDIUM

    def raw(self) -> dict:
        return {
            "type": self.type,
            "name": self.name,
            "value": self.value,
            "source": self.source,
            "confidence": self.confidence.value,
        }


@dataclass
class TechnologyDetection:
    technology: str
    detected: bool
    confidence: Confidence
    version: str | None = None
    evidence: list[EvidenceItem] = field(default_factory=list)


@dataclass
class PhpDetection:
    detected: bool
    version: str | None
    confidence: Confidence
    signals: list[EvidenceItem] = field(default_factory=list)
    phpinfo_exposed: bool = False
    version_source: str = ""
    stack: str | None = None


@dataclass
class VendorMarkers:
    server_header: str = ""
    distro_markers: list[str] = field(default_factory=list)
    module_markers: list[str] = field(default_factory=list)


@dataclass
class AssessmentResult:
    vulnerable_id: str | None
    state: FindingState
    severity: str
    cvss: float
    confidence: Confidence
    summary: str
    impact: str
    remediation: str
    detected_php_version: str | None
    fixed_version: str | None
    title: str
    references: list[str] = field(default_factory=list)
    evidence: list[EvidenceItem] = field(default_factory=list)
    vendor_patch_possible: bool = False


def pick_strongest(alts: list[AssessmentResult]) -> AssessmentResult | None:
    """Choose the most significant assessment by severity, then confidence."""
    best: AssessmentResult | None = None
    for alt in alts:
        if best is None:
            best = alt
            continue
        better = (
            SEVERITY_RANK.get(alt.severity, 0) > SEVERITY_RANK.get(best.severity, 0)
            or CONFIDENCE_RANK[alt.confidence] > CONFIDENCE_RANK[best.confidence]
        )
        if better:
            best = alt
    return best


def strongest_confidence(items: list[EvidenceItem]) -> Confidence:
    c = Confidence.LOW
    for item in items:
        if CONFIDENCE_RANK[item.confidence] > CONFIDENCE_RANK[c]:
            c = item.confidence
    return c


__all__ = [
    "AssessmentResult",
    "Confidence",
    "EvidenceItem",
    "FetchResult",
    "FindingState",
    "PhpDetection",
    "RedirectHop",
    "TechnologyDetection",
    "VendorMarkers",
    "pick_strongest",
    "strongest_confidence",
]
