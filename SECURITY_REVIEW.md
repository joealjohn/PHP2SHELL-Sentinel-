# Sentinel — Security Review

**Date:** 2026-10-23
**Scope:** `apps/api` (FastAPI), `apps/web` (Next.js 16), `packages/*`
(scanner/shared/vulndb), `docker-compose.yml`, `infra/`, CI workflow.
**Method:** static review of every security-relevant module, automated gates
(`bandit`, `pip-audit`, `npm audit`, `ruff`, `mypy`, `pytest`), and live
proof-of-concept checks against the local Docker stack (authorized, localhost
only). All confirmed issues were fixed in this session unless explicitly marked
residual/accepted.

---

## Verdict

| Area | Before | After |
|---|---|---|
| Auth / sessions / CSRF | Login throttle bypassable, auth mutations lacked CSRF | Hardened + regression tests |
| Rate limiting | Fail-open everywhere; XFF spoofable | Fail-closed for auth; XFF trusted only behind declared proxies |
| SSRF | Resolve-then-connect TOCTOU window | Unchanged (documented residual), per-hop validation confirmed |
| Email | Implicit TLS only; unsanitised user-editable headers | STARTTLS supported, headers sanitised, recipient validated |
| Web headers | No CSP, frame-ancestors, nosniff | CSP + security headers on every route |
| Docker exposure | Published on all host interfaces | Bound to `127.0.0.1` by default |
| Automated gates | 32 API tests, ruff errors | 46 API tests, ruff/mypy/bandit/pip-audit/npm audit clean |

Live proofs executed before the fixes (kept as audit evidence):

```
control same-IP logins : [401 x10, 429, 429]  → limiter works
spoofed X-Forwarded-For  : [401 x12]            → NO 429 (bypass confirmed)
POST /api/auth/logout (no CSRF header)          → 200 (CSRF gap confirmed)
GET /docs                                       → 200 (docs exposed)
```

---

## Findings & remediation

### S-01 — HIGH — Rate-limit bypass via spoofed `X-Forwarded-For` (FIXED)
`core/rate_limit.py::client_ip()` trusted the first XFF value unconditionally,
while `api` is published directly on the host. Rotating the header bypassed the
login/register/disclosure limits and poisoned audit IP records (proved live:
12/12 attempts accepted with spoofed IPs vs. 429 control).
**Fix:** XFF is ignored unless `TRUST_PROXY_HEADERS=1` *and* the direct peer is
inside `TRUSTED_PROXY_IPS` (IP or CIDR list); values must parse as IP
addresses. Tests: `TestClientIpTrust` (4 cases).

### S-02 — MEDIUM — Missing CSRF on auth mutations (FIXED)
`/auth/logout` and `/auth/change-password` are cookie-authenticated POSTs with
no `require_csrf`; logout succeeded without a token (proved live). Login and
register additionally had no origin check (login-CSRF surface).
**Fix:** both endpoints now depend on `require_csrf`; register/login/logout/
change-password enforce an Origin allow-list (`require_same_origin`) when the
header is present. Tests: `TestAuthHardening` (4 cases).

### S-03 — MEDIUM — Login brute force / account timing (FIXED)
Only a per-IP limiter existed (spoofable per S-01), and unknown accounts skipped
Argon2, leaking account existence via timing.
**Fix:** per-account fixed-window throttle (10 attempts / 15 min, keyed by
SHA-256 of the email) plus a dummy Argon2 verification for unknown users.
Login remains generic (`INVALID_CREDENTIALS`) for both cases.

### S-04 — MEDIUM — Rate limiter failed open on Redis outage (FIXED)
**Fix:** `enforce(..., fail_closed=...)`; login/register use
`RATE_LIMIT_FAIL_CLOSED=1` (default) and return `503 RATE_LIMIT_UNAVAILABLE`
instead of silently disabling brute-force protection. Other actions keep the
fail-open availability trade-off. Tests: `TestRateLimitFailClosed`.

### S-05 — MEDIUM — SMTP TLS was binary implicit-only (FIXED)
`SMTPProvider` passed `use_tls` only; a port-587 STARTTLS relay (the documented
production path) could not work. **Fix:** `SMTP_STARTTLS` config + `start_tls`
wiring (mutually exclusive with implicit TLS), 30 s timeout retained.

### S-06 — LOW — Email header injection surface (FIXED)
Subject is user-editable and was assigned to `MIME` headers directly; recipient
addresses originate from scraped `security.txt`/meta content. **Fix:**
`sanitize_header_value()` strips CR/LF from From/To/Subject; recipients are
validated with `email-validator` before use. Tests: `TestEmailHardening`.

### S-07 — MEDIUM — Web app had no security headers/CSP (FIXED)
**Fix:** `next.config.mjs` sets CSP (`default-src 'self'`, `frame-ancestors
'none'`, `object-src 'none'`), `X-Content-Type-Options`, `X-Frame-Options`,
`Referrer-Policy`, `Permissions-Policy` on all routes. Note: Next requires
`'unsafe-inline'` for bootstrap scripts/styles; a nonce-based policy would be a
future hardening step.

### S-08 — LOW — Report print iframe lacked sandbox (FIXED)
`iframe.srcdoc` executed same-origin. **Fix:** `sandbox="allow-same-origin
allow-modals"` (no scripts); print dialog still functions.

### S-09 — MEDIUM — All published ports bound to all interfaces (FIXED)
Despite the "local-only" promise, API/web/Mailpit/labs were reachable from the
LAN. **Fix:** everything is published as `127.0.0.1:<port>`; override the
host-port env vars as before.

### S-10 — MEDIUM — SSRF TOCTOU window (RESIDUAL, documented)
`urlguard` validates every DNS answer before each hop and the scanner
re-resolves per redirect, but `httpx` performs its own resolution at connect
time; a rebinding DNS server could answer differently in that window.
**Status:** accepted for a local-first tool; remediation would require pinning
the validated IP into the transport while preserving SNI/Host. Mitigations in
place: all-answer public check, per-hop revalidation, redirect cap, private
targets blocked unless explicitly enabled.

### S-11 — LOW — Unused `SESSION_SECRET` (FIXED)
Dead config was documented as required, implying a signing secret was in use.
**Fix:** removed from settings/docs/example (sessions are random opaque tokens
hashed at rest; CSRF is a per-session random value bound server-side).

### S-12 — LOW — CSRF comparison was not constant-time (FIXED)
**Fix:** `hmac.compare_digest` in `require_csrf`.

### S-13 — LOW — Docs/openapi exposed by default (FIXED)
**Fix:** `ENABLE_DOCS=0` default; `/docs` and `/openapi.json` are only mounted
when enabled. Test: `test_docs_disabled_by_default`.

### S-14 — LOW — Registration confirms account existence (ACCEPTED)
`409 EMAIL_TAKEN` is required for usable signup without email verification.
Compensating controls: 5 registrations/hour/IP, login rate limits, no
account-existence signal on login.

### S-15 — INFO — No HSTS (ACCEPTED)
The stack serves plain HTTP on localhost. HSTS is meaningless without TLS
termination; enable it at the reverse proxy when deployed behind HTTPS.
(2026-10-24: `COOKIE_SECURE` no longer exists — there are no cookies.)

---

## Confirmed sound (not regressions)

- Argon2id password hashing; 12+ char policy; opaque session tokens stored
  SHA-256-hashed with expiry/revocation; HttpOnly/SameSite=Lax cookies.
- Object ownership filters on every router (`404` for foreign IDs; IDOR tests
  pass); bearer tokens bypass CSRF correctly (can't be attached cross-site).
- SSRF guard: decimal/hex/octal/IPv6-mapped evasions blocked, metadata ranges,
  all-or-nothing DNS answer policy, per-hop redirect validation.
- Disclosure safety: recipients immutable via API (only contacts), duplicate
  guard `409`, test-email to self only, non-exploitation sentence preserved.
- Jinja HTML reports use `SandboxedEnvironment(autoescape=True)`.
- No `dangerouslySetInnerHTML`; external links use `rel="noreferrer"`.
- `bandit` 0 findings; `pip-audit` no known vulnerabilities; `npm audit` 0;
  `mypy` clean; dependency versions pinned.

## Residual risks

1. SSRF TOCTOU (S-10) — accepted, documented above.
2. Real SMTP delivery remains unverified (Mailpit only); STARTTLS path now
   implemented and unit-tested but not exercised against a real relay.
3. CSP relies on `'unsafe-inline'` for Next bootstrap (S-07 note).
4. GitHub Actions still cannot run (account billing lock, user-side); all
   gates were run locally.
5. Frontend still has no automated tests (build/typecheck only).

**Test evidence:** `apps/api` suite 46 passed (32 prior + 14 new hardening
tests); package suite 56 passed; ruff/mypy/bandit/pip-audit/npm audit clean.

---

# 2026-10-24 addendum — authentication removed entirely

**Decision (user):** for this loopback-only, single-user tool the session,
CSRF, and password systems added friction without adding real security.
They were **removed** on the user's explicit choice ("Remove auth
entirely").

Consequences:

- The fixes S-02/S-03/S-05/S-11/S-12 (CSRF on auth mutations, login timing,
  session TTL, unused secret, constant-time CSRF compare) are
  **superseded**: there is no login, no session, no CSRF token, and no
  password check anywhere. The `users` table keeps one seeded local owner
  (`OWNER_EMAIL`, default `owner@sentinel.local`) as the audit-log subject
  and disclosure test-email recipient; `password_hash` stores the literal
  placeholder `!disabled` (bandit-suppressed). The `sessions` table was
  dropped from the live database.
- Every service still binds 127.0.0.1 only. Expanding exposure is now a
  direct owner-trust decision — there is no auth boundary to rely on.
- Retained hardening still applies and keeps its tests: SSRF guard + per-hop
  rechecks, proxy-trust gating (`TRUST_PROXY_HEADERS`/`TRUSTED_PROXY_IPS`),
  fail-closed rate-limiter option (`RATE_LIMIT_FAIL_CLOSED`), interactive
  docs disabled by default (`ENABLE_DOCS=0`), SMTP STARTTLS + header
  hardening, TLS cert-faithful AIA chasing (never bypasses verification).
- Test evidence after removal: API suite **35 passed**, packages **59
  passed**, ruff/bandit/pip-audit/npm audit clean, web typecheck + build
  clean.
