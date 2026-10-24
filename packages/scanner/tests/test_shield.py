from __future__ import annotations

from sentinel_scanner.detectors.shield import (
    KIND_AES,
    KIND_CF,
    KIND_JS_ONLY,
    detect_shield,
)
from sentinel_scanner.http.client import FetchOutcome
from sentinel_scanner.models import Confidence, FetchResult


def _outcome(body: str, headers: dict[str, str] | None = None) -> FetchOutcome:
    result = FetchResult(url="https://t/", final_url="https://t/", status_code=200,
                         headers=headers or {}, body_text=body)
    return FetchOutcome(ok=True, status_code=200, result=result)


def test_infinityfree_challenge_body_fingerprint() -> None:
    page = (
        '<html><body><script type="text/javascript" src="/aes.js"></script>'
        "<script>function toNumbers(d){} var a=toNumbers('x');"
        'document.cookie="__test="+toHex(slowAES.decrypt(c,2,a,b));</script>'
    )
    det = detect_shield(_outcome(page))
    assert det.shielded is True
    assert det.kind == KIND_AES
    assert det.evidence[0].confidence == Confidence.HIGH
    assert det.evidence[0].type == "shield_signal"


def test_cloudflare_mitigated_header() -> None:
    det = detect_shield(_outcome("<html><title>t</title></html>",
                                 {"CF-Mitigated": "challenge"}))
    assert det.shielded is True
    assert det.kind == KIND_CF


def test_js_only_page_heuristic() -> None:
    det = detect_shield(_outcome("<html><body><script src='/app.js'></script>"))
    assert det.shielded is True
    assert det.kind == KIND_JS_ONLY


def test_real_page_is_not_shielded() -> None:
    body = ("<!DOCTYPE html><html><head><title>Real site</title></head>"
            "<body><div class='content'>Welcome text here</div>"
            "<script src='/assets/app.js'></script></body></html>")
    det = detect_shield(_outcome(body))
    assert det.shielded is False
    assert det.kind is None
    assert det.evidence == []


def test_long_or_empty_bodies_are_not_classified() -> None:
    assert detect_shield(_outcome("")).shielded is False
    assert detect_shield(_outcome("<script>x</script>" * 3000)).shielded is False
