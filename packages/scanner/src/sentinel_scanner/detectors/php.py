from __future__ import annotations

import re
from dataclasses import dataclass

from sentinel_scanner.http.client import FetchOutcome
from sentinel_scanner.models import (
    Confidence,
    EvidenceItem,
    FetchResult,
    PhpDetection,
    VendorMarkers,
)

_VERSION = r"(\d{1,2}\.\d{1,2}(?:\.\d{1,3})?)"

PHP_HEADER_RE = re.compile(r"PHP[/ ]" + _VERSION, re.IGNORECASE)
PHP_TOKEN_RE = re.compile(r"\bPHP\b", re.IGNORECASE)
PHPINFO_VERSION_RE = re.compile(r"PHP Version\s*(\d{1,2}\.\d{1,2}\.\d{1,3})")
PHPINFO_TITLE_RE = re.compile(r"<title>phpinfo\(\)</title>", re.IGNORECASE)
PHPSESSID_RE = re.compile(r"PHPSESSID=", re.IGNORECASE)
DISTRO_MARKER_RE = re.compile(
    r"(ubuntu|debian|suse|alpine|centos|fedora|rhel|sury|dotdeb|remi)", re.IGNORECASE
)

_CONF_RANK: dict[str, int] = {Confidence.LOW: 0, Confidence.MEDIUM: 1, Confidence.HIGH: 2}


@dataclass(frozen=True)
class PhpSignal:
    name: str
    source: str          # "response_header" | "response_cookie" | "phpinfo"
    value: str
    confidence: Confidence
    version: str | None = None

    @property
    def evidence_type(self) -> str:
        return {"response_header": "http_header",
                "response_cookie": "cookie_indicator",
                "phpinfo": "phpinfo_page"}[self.source]

    def as_evidence(self) -> EvidenceItem:
        return EvidenceItem(type=self.evidence_type, name=self.name,
                            value=self.value[:250], source="scanner_detectors/php",
                            confidence=self.confidence)


def _signals_from_headers(resp: FetchResult) -> list[PhpSignal]:
    signals: list[PhpSignal] = []
    xpb = resp.joined_header("x-powered-by")
    server = resp.joined_header("server")

    for label, header in (("X-Powered-By", xpb), ("Server", server)):
        if not header:
            continue
        m = PHP_HEADER_RE.search(header)
        if m:
            signals.append(PhpSignal(label, "response_header", header, Confidence.HIGH,
                                     version=m.group(1)))
        elif PHP_TOKEN_RE.search(header):
            signals.append(PhpSignal(label, "response_header", header, Confidence.MEDIUM))

    for v in (h for k, h in resp.headers.items() if k.lower() == "set-cookie"):
        if PHPSESSID_RE.search(v):
            signals.append(PhpSignal("Set-Cookie PHPSESSID", "response_cookie",
                                     "PHPSESSID=<redacted>", Confidence.MEDIUM))
    return signals


def _signal_from_phpinfo(resp: FetchResult) -> PhpSignal | None:
    m = PHPINFO_VERSION_RE.search(resp.body_text[:400000])
    if m:
        return PhpSignal("phpinfo() page", "phpinfo", f"PHP Version {m.group(1)}",
                         Confidence.HIGH, version=m.group(1))
    if PHPINFO_TITLE_RE.search(resp.body_text[:5000]):
        return PhpSignal("phpinfo() page", "phpinfo", "phpinfo() without version",
                         Confidence.MEDIUM)
    return None


def _norm_version(raw: str) -> str:
    return raw.strip().rstrip(".")


@dataclass(frozen=True)
class _Selection:
    version: str | None
    confidence: Confidence
    source_name: str


def _select_version(signals: list[PhpSignal]) -> _Selection:
    carriers = [s for s in signals if s.version is not None]
    carriers.sort(key=lambda s: _CONF_RANK[s.confidence], reverse=True)
    if carriers:
        return _Selection(carriers[0].version, carriers[0].confidence, carriers[0].name)
    top = max(signals, key=lambda s: _CONF_RANK[s.confidence])
    return _Selection(None, top.confidence, top.name)


def extract_vendor_markers(resp: FetchResult | None) -> VendorMarkers:
    markers = VendorMarkers()
    if resp is None:
        return markers
    server = resp.joined_header("server")[:160]
    markers.server_header = server
    m = DISTRO_MARKER_RE.search(server or "")
    if m:
        markers.distro_markers.append(m.group(1).title())
    for token in re.split(r"[\s()/]+", server or ""):
        if token.lower() in ("fpm", "fastcgi", "mod_php", "php-fpm"):
            markers.module_markers.append(token)
    return markers


def detect_php(home_outcome: FetchOutcome,
                phpinfo_outcome: FetchOutcome | None = None,
                extra_signals: list[PhpSignal] | None = None,
                ) -> PhpDetection:
    """Combine multiple independent PHP signals into a single detection.

    Version-carrying evidence strengths:
    - X-Powered-By/Server: PHP/x.y.z -> HIGH, explicit upstream version
    - phpinfo() body: PHP Version x.y.z -> HIGH, explicit upstream version
    - Set-Cookie: PHPSESSID -> MEDIUM, no version
    """
    signals: list[PhpSignal] = []
    phpinfo_exposed = False

    if home_outcome.ok and home_outcome.result is not None:
        signals.extend(_signals_from_headers(home_outcome.result))
        if PHPINFO_TITLE_RE.search(home_outcome.result.body_text[:5000]):
            phpinfo_exposed = True

    if phpinfo_outcome is not None and phpinfo_outcome.ok and phpinfo_outcome.result:
        sig = _signal_from_phpinfo(phpinfo_outcome.result)
        if sig:
            signals.append(sig)
            phpinfo_exposed = True

    if extra_signals:
        seen: set[tuple[str, str, str]] = {
            (s.name, s.source, s.value) for s in signals
        }
        for sig in extra_signals:
            key = (sig.name, sig.source, sig.value)
            if key not in seen:
                seen.add(key)
                signals.append(sig)

    if not signals:
        return PhpDetection(detected=False, version=None, confidence=Confidence.LOW,
                            signals=[], phpinfo_exposed=phpinfo_exposed)

    selection = _select_version(signals)
    return PhpDetection(
        detected=True,
        version=selection.version,
        confidence=selection.confidence,
        signals=[s.as_evidence() for s in signals],
        phpinfo_exposed=phpinfo_exposed,
        version_source=selection.source_name,
    )
