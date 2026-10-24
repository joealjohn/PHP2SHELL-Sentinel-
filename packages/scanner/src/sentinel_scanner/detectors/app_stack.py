"""Application-stack fingerprints that survive header stripping.

Read-only signals collected from already-fetched responses: framework
session cookies, CMS ``<meta name=generator>`` tags, well-known asset
paths, and PHP runtime headers that appear on secondary responses (for
example error pages) even when the application overrides them on the
homepage.

None of these signals disclose a PHP runtime version on their own; their
job is to classify a header-hidden target as "PHP present - version not
disclosed" (which can never produce a CVE verdict) instead of "no data",
and to name the application stack when it is fingerprintable.
"""
from __future__ import annotations

import re

from sentinel_scanner.detectors.php import PHP_HEADER_RE, PhpSignal
from sentinel_scanner.models import Confidence, FetchResult

# cookie-name-lower -> (signal label, confidence, stack name or None)
_COOKIE_SIGNALS: dict[str, tuple[str, Confidence, str | None]] = {
    "phpsessid": ("PHP (session cookie)", Confidence.MEDIUM, None),
    "laravel_session": ("Laravel (session cookie)", Confidence.MEDIUM, "Laravel"),
    "xsrf-token": (
        "Laravel/Symfony-class app (XSRF cookie)", Confidence.LOW, None),
    "ci_session": ("CodeIgniter (session cookie)", Confidence.MEDIUM, "CodeIgniter"),
    "wordpress_logged_in": ("WordPress (auth cookie)", Confidence.MEDIUM, "WordPress"),
    "wp-settings-": ("WordPress (ui settings cookie)", Confidence.MEDIUM, "WordPress"),
}

_GENERATOR_RE = re.compile(
    r"<meta[^>]+name=[\"']generator[\"'][^>]*content=[\"']([^\"']{1,120})[\"']"
    r"|<meta[^>]+content=[\"']([^\"']{1,120})[\"'][^>]*name=[\"']generator[\"']",
    re.IGNORECASE,
)
_PHP_STACK_RE = re.compile(
    r"(wordpress|joomla|drupal|phpbb|magento|prestashop|typo3|laravel|symfony|"
    r"codeigniter|yii|cakephp|mediawiki|dokuwiki|phpmyadmin)",
    re.IGNORECASE,
)
_STACK_DISPLAY = {
    "wordpress": "WordPress",
    "joomla": "Joomla",
    "drupal": "Drupal",
    "phpbb": "phpBB",
    "magento": "Magento",
    "prestashop": "PrestaShop",
    "typo3": "TYPO3",
    "laravel": "Laravel",
    "symfony": "Symfony",
    "codeigniter": "CodeIgniter",
    "yii": "Yii",
    "cakephp": "CakePHP",
    "mediawiki": "MediaWiki",
    "dokuwiki": "DokuWiki",
    "phpmyadmin": "phpMyAdmin",
}
_WP_PATH_RE = re.compile(r"/wp-content/|/wp-includes/|/wp-json\b", re.IGNORECASE)


def _cookie_signals(resp: FetchResult, signals: list[PhpSignal],
                    stack: list[str]) -> None:
    seen: set[str] = set()
    for k, v in resp.headers.items():
        if k.lower() != "set-cookie":
            continue
        name = v.split("=", 1)[0].strip().lower()
        if not name or name in seen:
            continue
        seen.add(name)
        for key, (label, conf, stack_name) in _COOKIE_SIGNALS.items():
            prefix_match = key.endswith("-") and name.startswith(key)
            if name != key and not prefix_match:
                continue
            signals.append(PhpSignal(
                label, "response_cookie", f"{name}=<redacted>", conf))
            if stack_name:
                stack.append(stack_name)


def _header_signals(resp: FetchResult, signals: list[PhpSignal]) -> None:
    """PHP runtime headers on secondary responses (e.g. error pages)."""
    for label, header in (
        ("X-Powered-By", resp.joined_header("x-powered-by")),
        ("Server", resp.joined_header("server")),
    ):
        if not header:
            continue
        m = PHP_HEADER_RE.search(header)
        if m:
            signals.append(PhpSignal(
                label, "response_header", header[:160], Confidence.HIGH,
                version=m.group(1)))


def _generator_signals(resp: FetchResult, signals: list[PhpSignal],
                       stack: list[str]) -> None:
    m = _GENERATOR_RE.search(resp.body_text or "")
    if m is None:
        return
    value = (m.group(1) or m.group(2) or "").strip()
    if not value:
        return
    sm = _PHP_STACK_RE.search(value)
    if sm is None:
        return  # generator names a non-PHP stack (hugo, gatsby, ...) - ignore
    signals.append(PhpSignal(
        "generator meta tag", "body_marker", value[:120], Confidence.HIGH))
    key = sm.group(1).lower()
    app = _STACK_DISPLAY.get(key, key.capitalize())
    vm = re.search(r"(\d+(?:\.\d+)+)", value)
    stack.append(f"{app} {vm.group(1)}" if vm else app)


def _wp_path_signals(resp: FetchResult, signals: list[PhpSignal],
                     stack: list[str]) -> None:
    if _WP_PATH_RE.search(resp.body_text or ""):
        signals.append(PhpSignal(
            "WordPress asset paths", "body_marker",
            "/wp-content/ or /wp-includes/ or /wp-json referenced",
            Confidence.MEDIUM))
        stack.append("WordPress")


def stack_signals(resp: FetchResult) -> tuple[list[PhpSignal], str | None]:
    """Return (php-presence signals, stack name or None) for one response."""
    signals: list[PhpSignal] = []
    stack_hits: list[str] = []
    _cookie_signals(resp, signals, stack_hits)
    _header_signals(resp, signals)
    _generator_signals(resp, signals, stack_hits)
    _wp_path_signals(resp, signals, stack_hits)
    stack: str | None = stack_hits[0] if stack_hits else None
    return signals, stack
