from __future__ import annotations

import re

from sentinel_scanner.http.client import FetchOutcome
from sentinel_scanner.models import (
    Confidence,
    EvidenceItem,
    FetchResult,
    TechnologyDetection,
)

_VERSION = r"(\d+(?:\.\d+)+)"

_XPB_NODE = re.compile(r"X-Powered-By.*?(Express|Next\.js|PHP|ASP\.NET)", re.IGNORECASE)


def _ev(name: str, value: str, source: str, confidence: Confidence) -> EvidenceItem:
    return EvidenceItem(type="http_header", name=name, value=value[:250], source=source,
                        confidence=confidence)


def _from_response(resp: FetchResult) -> list[TechnologyDetection]:
    out: list[TechnologyDetection] = []
    server = resp.joined_header("server")[:200]
    xpb = resp.joined_header("x-powered-by")[:200]
    cookies = " ".join(v for k, v in resp.headers.items() if k == "set-cookie")
    body = resp.body_text[:300000]

    # ── Apache ────────────────────────────────────────────────────────────
    if _apache_re.search(server or ""):
        m = _apache_ver.search(server or "")
        out.append(TechnologyDetection(
            "Apache", True, Confidence.HIGH,
            version=m.group(1) if m else None,
            evidence=[_ev("Server", server, "response", Confidence.HIGH)],
        ))

    # ── Nginx ─────────────────────────────────────────────────────────────
    if _nginx_re.search(server or ""):
        m = _nginx_ver.search(server or "")
        out.append(TechnologyDetection(
            "Nginx", True, Confidence.HIGH,
            version=m.group(1) if m else None,
            evidence=[_ev("Server", server, "response", Confidence.HIGH)],
        ))

    # ── LiteSpeed ─────────────────────────────────────────────────────────
    if _litespeed_re.search(server or ""):
        out.append(TechnologyDetection(
            "LiteSpeed", True, Confidence.HIGH,
            evidence=[_ev("Server", server, "response", Confidence.HIGH)],
        ))

    # ── Cloudflare ────────────────────────────────────────────────────────
    cf_ray = resp.joined_header("cf-ray")
    if cf_ray or resp.joined_header("cf-cache-status"):
        evs = []
        if cf_ray:
            evs.append(_ev("cf-ray", cf_ray, "response", Confidence.HIGH))
        out.append(TechnologyDetection(
            "Cloudflare", True, Confidence.HIGH, version=None, evidence=evs))

    # ── PHP ───────────────────────────────────────────────────────────────
    php_match = _php_ver.search(xpb) if xpb else None
    if php_match:
        out.append(TechnologyDetection(
            "PHP", True, Confidence.HIGH, version=php_match.group(1),
            evidence=[_ev("X-Powered-By", xpb, "response", Confidence.HIGH)]))
    elif "php" in (server or "").lower():
        out.append(TechnologyDetection(
            "PHP", True, Confidence.MEDIUM,
            evidence=[_ev("Server", server, "response", Confidence.MEDIUM)]))
    elif "phpsessid=" in cookies.lower():
        out.append(TechnologyDetection(
            "PHP", True, Confidence.MEDIUM,
            evidence=[_ev("Set-Cookie", "PHPSESSID", "response", Confidence.MEDIUM)]))

    # ── Node.js (express / generic) ───────────────────────────────────────
    if xpb and re.search(r"express|node\.?js|sails|proxy-1", xpb, _RXI):
        out.append(TechnologyDetection(
            "Node.js", True, Confidence.HIGH,
            evidence=[_ev("X-Powered-By", xpb, "response", Confidence.HIGH)]))

    # ── ASP.NET ───────────────────────────────────────────────────────────
    if xpb and "asp.net" in xpb.lower():
        out.append(TechnologyDetection(
            "ASP.NET", True, Confidence.HIGH,
            evidence=[_ev("X-Powered-By", xpb, "response", Confidence.HIGH)]))
    elif re.search(r"asp\.net|\.aspx|__viewstate|aspnetsessionid",
                   body + cookies, _RXI):
        conf = Confidence.MEDIUM if "aspnetsessionid" in cookies.lower() or "__viewstate" in body.lower() else Confidence.LOW
        out.append(TechnologyDetection(
            "ASP.NET", True, conf,
            evidence=[_ev("Body/Cookie", "ASP.NET indicators", "response", conf)]))

    # ── Next.js ───────────────────────────────────────────────────────────
    nxt = []
    if resp.joined_header("x-nextjs-cache") or resp.joined_header("x-nextjs-postid"):
        nxt.append(_ev("x-nextjs-*", "present", "response", Confidence.HIGH))
    if "__NEXT_DATA__" in body:
        nxt.append(_ev("__NEXT_DATA__", "found", "body", Confidence.HIGH))
    if '/_next/' in body:
        nxt.append(_ev("/_next/", "asset paths", "body", Confidence.HIGH))
    if xpb and "next.js" in xpb.lower():
        nxt.append(_ev("X-Powered-By", xpb, "response", Confidence.HIGH))
    if nxt:
        out.append(TechnologyDetection("Next.js", True, _strongest(nxt), evidence=nxt))

    # ── WordPress ─────────────────────────────────────────────────────────
    wp = []
    gen = _generator(body)
    if gen and "wordpress" in gen.lower():
        wp.append(_ev("meta generator", gen, "body", Confidence.HIGH))
    if "/wp-content/" in body:
        wp.append(_ev("/wp-content/", "referenced", "body", Confidence.HIGH))
    if "wp-json" in body:
        wp.append(_ev("wp-json", "referenced", "body", Confidence.MEDIUM))
    if 'wp_content' in cookies.lower() or "wordpress_logged_in" in cookies.lower():
        wp.append(_ev("Set-Cookie", "wordpress_*", "response", Confidence.MEDIUM))
    if wp:
        out.append(TechnologyDetection("WordPress", True, _strongest(wp), evidence=wp))

    # ── Laravel ───────────────────────────────────────────────────────────
    if "laravel_session=" in cookies.lower() or "xsrf-token=" in cookies.lower():
        out.append(TechnologyDetection(
            "Laravel", True, Confidence.MEDIUM,
            evidence=[_ev("Set-Cookie", "laravel_session", "response", Confidence.MEDIUM)]))

    # ── Symfony ───────────────────────────────────────────────────────────
    if resp.joined_header("x-debug-token") or "symfony" in (body[:2000] + gen).lower():
        out.append(TechnologyDetection(
            "Symfony", True, Confidence.MEDIUM,
            evidence=[_ev("x-debug-token", resp.joined_header("x-debug-token") or "symfony",
                          "response", Confidence.MEDIUM)]))

    return out


_PHPANY = re.compile(r"php", re.IGNORECASE)
_php_ver = re.compile(r"PHP[/ ]" + _VERSION, re.IGNORECASE)
_apache_re = re.compile(r"apache", re.IGNORECASE)
_apache_ver = re.compile(r"Apache[/ ]" + _VERSION, re.IGNORECASE)
_nginx_re = re.compile(r"nginx", re.IGNORECASE)
_nginx_ver = re.compile(r"nginx[/ ]" + _VERSION, re.IGNORECASE)
_litespeed_re = re.compile(r"litespeed", re.IGNORECASE)
_RXI = re.IGNORECASE
_generator_re = re.compile(
    r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)', re.IGNORECASE)


def _generator(body: str) -> str:
    m = _generator_re.search(body or "")
    return m.group(1) if m else ""


def _strongest(evs: list[EvidenceItem]) -> Confidence:
    best = Confidence.LOW
    for e in evs:
        if CONF[e.confidence] > CONF[best]:
            best = e.confidence
    return best


CONF = {Confidence.LOW: 0, Confidence.MEDIUM: 1, Confidence.HIGH: 2}


def run_technology_fingerprinting(outcome: FetchOutcome) -> list[TechnologyDetection]:
    if not outcome.ok or outcome.result is None:
        return []
    return _from_response(outcome.result)
