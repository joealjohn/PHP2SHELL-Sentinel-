"""Bot-challenge / shield fingerprinting for honest inconclusive scans.

A target behind a JavaScript-only bot challenge (the InfinityFree
``__test`` / ``aes.js`` mechanism, a Cloudflare ``cf-mitigated: challenge``
response, or generic script-only markup) serves different content to a
non-browser client.  Detection data collected from such a response does
NOT describe the real application, so the scan must be reported as
inconclusive rather than as a clean bill of health.

This module only observes the already-fetched response.  It never
attempts to solve, compute, or bypass any challenge: that would be
circumvention of the target protection, which a non-exploitative
visibility scanner does not do.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from sentinel_scanner.http.client import FetchOutcome
from sentinel_scanner.models import Confidence, EvidenceItem

KIND_CF = "cloudflare_challenge"
KIND_AES = "js_challenge_infinityfree"
KIND_JS_ONLY = "js_only_page"

_KIND_LABELS = {
    KIND_CF: "Cloudflare challenge (cf-mitigated response header)",
    KIND_AES: "JavaScript bot-challenge (InfinityFree-style __test cookie)",
    KIND_JS_ONLY: "JavaScript-only markup without page content",
}

_AES_RE = re.compile(r"toNumbers\(|slowAES|__test\s*=", re.IGNORECASE)
_TEXTY_MARKERS = ("</html>", "<title", "<h1", "<p>", "<p ", "<div", "<span")


@dataclass(frozen=True)
class ShieldDetection:
    shielded: bool
    kind: str | None = None
    evidence: list[EvidenceItem] = field(default_factory=list)


def _js_only_page(body: str) -> bool:
    """Conservative heuristic for JS-only challenge markup.

    Requires: small body, at least one script tag, no title/paragraph/
    heading/container markup and no document close.  Real applications
    essentially never satisfy all four conditions.
    """
    if not body or len(body) > 3000:
        return False
    if "<script" not in body.lower():
        return False
    lowered = body.lower()
    return not any(marker in lowered for marker in _TEXTY_MARKERS)


def detect_shield(outcome: FetchOutcome | None) -> ShieldDetection:
    """Classify a homepage outcome as shielded/inconclusive when warranted."""
    if outcome is None or not outcome.ok or outcome.result is None:
        return ShieldDetection(False, None, [])
    resp = outcome.result
    kind: str | None = None
    if "challenge" in resp.joined_header("cf-mitigated").lower():
        kind = KIND_CF
    if kind is None and _AES_RE.search(resp.body_text or ""):
        kind = KIND_AES
    if kind is None and _js_only_page(resp.body_text or ""):
        kind = KIND_JS_ONLY
    if kind is None:
        return ShieldDetection(False, None, [])
    confidence = Confidence.MEDIUM if kind == KIND_JS_ONLY else Confidence.HIGH
    return ShieldDetection(
        shielded=True,
        kind=kind,
        evidence=[
            EvidenceItem(
                type="shield_signal",
                name=_KIND_LABELS[kind],
                value=(resp.body_text or "")[:200],
                source="scanner_detectors/shield",
                confidence=confidence,
            )
        ],
    )
