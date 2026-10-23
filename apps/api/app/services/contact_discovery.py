from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import urljoin, urlsplit

import dns.resolver
from sentinel_shared.urlguard import normalize_url

from app.core.config import get_settings
from app.services.email import get_email_provider  # noqa: F401


@dataclass
class ContactCandidate:
    email: str | None
    contact_url: str | None
    source: str
    source_url: str | None
    confidence: str
    policy_url: str | None = None
    encryption_url: str | None = None
    preferred_languages: str | None = None
    mx_verified: bool = False


SECURITY_TXT_PATHS = ("/.well-known/security.txt", "/security.txt")

FIELD_RE = re.compile(r"^(?P<field>[A-Za-z-]+):\s*(?P<value>.*?)\s*$", re.MULTILINE)
MAILTO_RE = re.compile(r"mailto:([^\"'?>]+@[a-z0-9._-]+)", re.IGNORECASE)
SECURITY_LINK_RE = re.compile(
    r"<a[^>]+href=[\"']([^\"']*(?:security|vulnerab)[^\"']*)[\"']", re.IGNORECASE)
DELAY_RE = re.compile(r"^([0-9]{1,4})[dsh]?$", re.IGNORECASE)


def parse_security_txt(body: str) -> dict[str, list[str]]:
    fields: dict[str, list[str]] = {}
    for match in FIELD_RE.finditer(body or ""):
        f = match.group("field").lower()
        v = match.group("value")
        fields.setdefault(f, []).append(v)
    return fields


class ContactDiscoveryError(Exception):
    pass


def _should_allow_private() -> bool:
    return get_settings().allow_private_targets


async def _fetch(url: str, client, follow: bool):
    outcome = await client.get(url, follow_redirects=follow)
    return outcome


async def discover_contacts(base_url: str, client) -> list[ContactCandidate]:
    """Discover security contact candidates for an authorized asset.

    Priority (RFC 9116 preferred): /.well-known/security.txt, /security.txt,
    then security page links on the homepage, then conventional fallback
    mailboxes (security@, security-team@, support@, abuse@) only when the
    domain's MX records exist. No employee emails are harvested.
    """
    candidates: list[ContactCandidate] = []
    seen_emails: set[str] = set()
    base = normalize_url(base_url).rstrip("/")

    for path in SECURITY_TXT_PATHS:
        url = base + path
        outcome = await _fetch(url, client, follow=False)
        if outcome.ok and outcome.result and outcome.result.status_code == 200:
            body = outcome.result.body_text
            fields = parse_security_txt(body)
            contact_urls = fields.get("contact", [])
            policy = (fields.get("policy") or [None])[0]
            encryption = (fields.get("encryption") or [None])[0]
            langs = ",".join(fields.get("preferred-languages", [])) or None
            for cu in contact_urls:
                if _is_https(cu):
                    candidates.append(ContactCandidate(
                        email=None, contact_url=cu, source="security_txt",
                        source_url=url, confidence="HIGH",
                        policy_url=policy, encryption_url=encryption,
                        preferred_languages=langs,
                        mx_verified=_verify_mx(_domain_of(base)),
                    ))
                elif cu.lower().startswith("mailto:"):
                    addr = MAILTO_RE.search(cu)
                    email = (addr.group(1) if addr else None)
                    if email and email not in seen_emails:
                        seen_emails.add(email)
                        candidates.append(ContactCandidate(
                            email=email, contact_url=None, source="security_txt",
                            source_url=url, confidence="HIGH",
                            policy_url=policy, encryption_url=encryption,
                            preferred_languages=langs,
                            mx_verified=_verify_mx(_domain_of(email)),
                        ))
            if candidates:
                return _dedupe(candidates)

    home = await _fetch(base, client, follow=True)
    if home.ok and home.result is not None:
        body = home.result.body_text[:300000]
        for href in SECURITY_LINK_RE.findall(body) + MAILTO_RE.findall(body):
            target = urljoin(base, href) if not href.startswith("mailto:") else href
            if href.lower().startswith("mailto:"):
                addr = MAILTO_RE.search(href)
                email = addr.group(1) if addr else None
                if email and email not in seen_emails:
                    seen_emails.add(email)
                    candidates.append(ContactCandidate(
                        email=email, contact_url=None, source="security_page",
                        source_url=base, confidence="HIGH",
                        mx_verified=_verify_mx(_domain_of(email))))
            elif _is_https(target):
                candidates.append(ContactCandidate(
                    email=None, contact_url=target, source="security_page",
                    source_url=base, confidence="MEDIUM"))

    if not candidates:
        domain = _domain_of(base)
        if domain:
            mx = _verify_mx(domain)
            for name, conf in (("security", "MEDIUM"), ("security-team", "MEDIUM"),
                               ("support", "LOW"), ("abuse", "LOW")):
                email = f"{name}@{domain}"
                if email in seen_emails:
                    continue
                seen_emails.add(email)
                candidates.append(ContactCandidate(
                    email=email, contact_url=None, source=f"conventional_{name}",
                    source_url=None, confidence=conf, mx_verified=mx))

    return _dedupe(candidates)


def _dedupe(candidates: list[ContactCandidate]) -> list[ContactCandidate]:
    out: list[ContactCandidate] = []
    seen: set[str] = set()
    for c in candidates:
        key = c.email or c.contact_url or ""
        if not key or key in seen:
            continue
        seen.add(key)
        out.append(c)
    return out


def _is_https(url: str) -> bool:
    return bool(re.match(r"^https://", (url or "").strip(), re.IGNORECASE))


def _domain_of(url_or_email: str) -> str:
    host = urlsplit(url_or_email).hostname
    if not host and "@" in url_or_email:
        host = url_or_email.rsplit("@", 1)[-1]
    return (host or "").lower()


def _verify_mx(domain: str) -> bool:
    if not domain:
        return False
    try:
        resolver = dns.resolver.Resolver(configure=True)
        resolver.lifetime = 10
        return bool(resolver.resolve(domain, "MX"))
    except Exception:
        return False


CONTACT_CONFIDENCE_BY_SOURCE = {
    "security_txt": "HIGH",
    "security_page": "HIGH",
    "conventional_security": "MEDIUM",
    "conventional_security-team": "MEDIUM",
    "conventional_support": "LOW",
    "conventional_abuse": "LOW",
}
