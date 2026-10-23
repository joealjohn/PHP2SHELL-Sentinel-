# Sentinel

Local-first web-vulnerability monitoring for sites you own or are authorized
to test. Sentinel scans non-invasively, verifies findings with version
evidence, manages remediation, and drafts responsible-disclosure emails --
it never sends payloads and never touches the target beyond what a
visibility scanner would.

Targets https sites too: certificate verification is always on, and missing
intermediates are chased automatically via the certificate's AIA extension
(RFC 5280) instead of weakening trust.

## Features

| Area | What it does |
|---|---|
| Asset management | Register targets with SSRF-guarded URL normalization, mandatory authorization confirmation, monitoring intervals |
| PHP detection | `X-Powered-By`, `Server` header, phpinfo scraping, HTML body markers, vendor/distro markers, redirect hops |
| PHP2Shell assessment | CVE-2026-109618 / CVE-2026-109619 risk assessment via version comparison only |
| Evidence gathering | Timestamped, versioned evidence rows (headers, version comparisons, non-exploitation notices) |
| Contact discovery | `/.well-known/security.txt` (RFC 9116), legacy `/security.txt`, HTML meta/link scanning |
| Disclosure engine | Draft, test email to yourself, approve, send (SMTP/Mailpit); duplicate protection and cancellation |
| Remediation verification | "Verify fix" re-scan marks a finding PATCHED only when fresh evidence proves the new version is fixed |
| Reports | JSON + HTML reports with non-exploitation statements; browser PDF export |
| Dashboard | Grouped sidebar with live badges, 14-day trends, posture score, audit trail, light/dark theme |

## How it works

```
Browser ──▶ Next.js web (:3000) ──▶ FastAPI (:8000) ──▶ Celery worker
                                        │                 scans + contact
                                        ▼                 discovery + e-mail
                            PostgreSQL (schema)  ◀───────┘
                            Redis (broker + rate limit)
                            Mailpit (SMTP sink, UI :8025)
```

1. Asset creation is SSRF-guarded: every URL is normalized, resolved, and
   validated before any request is made -- private/metadata targets are
   rejected.
2. A scan queues through Celery. The worker executes a bounded, read-only
   scan: max 8 redirects, 2 MiB responses, 5 requests/second, 4 parallel
   fetches, 60 s budget, per-hop SSRF re-validation after every redirect.
3. Detection results feed the risk assessor, which compares the detected PHP
   version against the CVE database (`packages/vulnerability-db`). No
   payloads exist in the codebase.
4. Confidence is honest: findings stop at HIGH_CONFIDENCE (or
   LIKELY_VULNERABLE when distro/vendor markers are present). Only a fresh
   re-scan proving the version is fixed can mark PATCHED.

## Quick start (Docker)

```powershell
Copy-Item .env.example .env      # single-user app; optionally set OWNER_EMAIL
docker compose up --build -d
docker compose --profile lab up --build -d lab-vulnerable lab-patched
```

| Service | URL |
|---|---|
| Web app | http://localhost:3000 |
| API | http://127.0.0.1:8000 |
| Mail UI (Mailpit) | http://localhost:8025 |
| Test labs | http://localhost:8081 - 8086 |

Sentinel is a single-user local deployment: there is no login. All services
bind to loopback only. The lab profile adds six vulnerable/patched nginx
targets on the docker network; scanning them requires
`SCAN_ALLOW_PRIVATE_TARGETS=1` in `.env`.

## Configuration

Full reference in [.env.example](.env.example). Key settings:

| Variable | Default | Purpose |
|---|---|---|
| `OWNER_EMAIL` | `owner@sentinel.local` | Audit-log subject and disclosure test-email recipient |
| `SCAN_ALLOW_PRIVATE_TARGETS` | `0` | Danger toggle for local lab scanning only |
| `TRUST_PROXY_HEADERS` | `0` | Ignore `X-Forwarded-For` unless behind a proxy you control |
| `RATE_LIMIT_FAIL_CLOSED` | `0` | Refuse sensitive actions while Redis is down |
| `ENABLE_DOCS` | `0` | Interactive API docs (keep off outside local dev) |
| `SMTP_HOST/PORT/...` | Mailpit | Outbound email sink; `SMTP_TLS=1` for 587/STARTTLS relays |
| `SSL_CERT_FILE` | compose mount | CA bundle (`infra/tls/ca-bundle.pem`) for TLS verification |

## Security design

| Concern | Implementation |
|---|---|
| SSRF | Full resolve-then-connect guard, per-hop revalidation, decimal/IP evasion blocked, metadata ranges blocked |
| TLS | certifi-backed context, `CERT_REQUIRED` always; AIA chasing fetches missing intermediates without ever disabling verification |
| Rate limiting | Per-IP Redis windows, `429` + `Retry-After`, optional fail-closed mode |
| Secrets | Headers redacted in evidence, exceptions log type-only, consistent error envelopes without stack traces |
| Response hardening | `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, `Permissions-Policy` |
| Audit | Every security-relevant action logged (`SCAN_QUEUED`, `FINDING_OPENED`, `DISCLOSURE_SENT`, ...) |

TLS verification is never bypassed. When a handshake fails:

- "unable to get local issuer certificate" -- the server omits intermediates;
  Sentinel fetches them from the AIA `CA Issuers` URL the certificate itself
  advertises, retries the hop, and fails with
  `TLS_CERT_CHAIN_INCOMPLETE` if that does not complete the chain.
- "Hostname mismatch, certificate is not valid for..." -- the cert does not
  cover the exact URL host (a wildcard covers one label: `exams.host`
  matches `*.host`, `www.exams.host` does not). Reports
  `TLS_CERT_HOSTNAME_MISMATCH`.

To trust a custom/private CA, append its public certificate to
`infra/tls/ca-bundle.pem` and restart api + worker. Never add private keys.

## Testing and quality gates

```powershell
python -m pytest apps/api/tests packages/shared/tests packages/scanner/tests packages/vulnerability-db/tests -q   # 95 tests
python -m ruff check .                 # 0 errors
python -m bandit -q -r apps/api/app packages/shared/src packages/scanner/src
python -m pip_audit
cd apps/web; npm run typecheck; npm run build
```

35 API integration tests plus 60 package tests are green. Manual end-to-end
walkthrough (lab + Mailpit) is in
[STARTUP_TESTING_GUIDE.md](STARTUP_TESTING_GUIDE.md).

## API overview

Every request runs as the single local owner. Interactive docs are gated
behind `ENABLE_DOCS=1`.

| Route | Purpose |
|---|---|
| `GET/POST /api/assets`, `GET/PATCH/DELETE /api/assets/{id}` | Assets (URL guard on create) |
| `POST /api/assets/{id}/scan`, `GET /api/assets/{id}/scans` | Queue a scan / scan history |
| `POST /api/assets/{id}/contacts/discover`, `GET /api/assets/{id}/contacts` | Contact workflow |
| `GET /api/scans`, `GET /api/scans/{id}`, `POST /api/scans/{id}/cancel` | Scan management |
| `GET /api/findings`, `GET /api/findings/{id}` (+evidence, disclosures) | Findings |
| `POST /api/findings/{id}/rescan` / `verify-fix` / `close` | Finding operations |
| `POST /api/findings/{id}/disclosure`, `PATCH /api/disclosures/{id}` | Draft / edit email |
| `POST /api/disclosures/{id}/mark-pending` / `test-email` / `approve` / `send-now` / `cancel` | Disclosure lifecycle |
| `GET /api/reports` (+ `.json` / `.html` per finding) | Reports |
| `GET /api/notifications`, `GET /api/audit`, `GET /api/metrics/summary` | Notification center, audit trail, dashboard |
| `GET /health`, `GET /ready` | Liveness / readiness |

Errors are consistent: `{"error": {"code": "...", "message": "..."}}`.
Recognition codes include `RATE_LIMITED`, `AUTHORIZATION_REQUIRED`,
`SCAN_ALREADY_RUNNING`, `NO_CONTACT`, `DUPLICATE_DISCLOSURE`,
`INVALID_TRANSITION`, `PRIVATE_TARGET`, `METADATA_ENDPOINT`,
`TLS_CERT_CHAIN_INCOMPLETE`, `TLS_CERT_HOSTNAME_MISMATCH`.

## Project structure

```
Sentinel/
+-- apps/api            FastAPI service (routers, services, Celery workers, Alembic migrations)
+-- apps/web            Next.js 16 frontend (App Router, Tailwind v4, light/dark theme)
+-- packages/shared     SSRF url-guard, version comparison, header redaction
+-- packages/vulnerability-db   CVE data + loader (data/php2shell.json)
+-- packages/scanner    HTTP client (TLS/AIA), PHP detectors, risk assessor, evidence
+-- tests/labs/php2shell    Six Dockerized lab targets (vulnerable/patched/hidden/...)
+-- infra/docker        api.Dockerfile + web.Dockerfile
+-- infra/tls           ca-bundle.pem (public certificates only)
+-- docker-compose.yml  Full stack (+ profile: lab)
```

There is no login: the app is single-user by design, with one seeded local
owner row (`OWNER_EMAIL`). Points requiring authorization consent still
exist everywhere an outside host is involved (asset authorization checkbox,
SSRF guard, disclosure approval flow).

## Documentation

| File | Contents |
|---|---|
| [STARTUP_TESTING_GUIDE.md](STARTUP_TESTING_GUIDE.md) | Install via Docker, verify stack health, E2E walkthrough, troubleshooting, test gates |
| [SECURITY_REVIEW.md](SECURITY_REVIEW.md) | Security audit findings, fixes, and accepted residual risks |
| [SECURITY.md](SECURITY.md) | Repository security policy |
| [.env.example](.env.example) | Copy/paste configuration template |

## Design decisions

1. No exploit payloads -- the scanner's HTTP client cannot carry one. Risk
   assessment is version math; evidence is uppercase statements of observation.
2. HIGH_CONFIDENCE is the remote reporting ceiling. No "confirmed
   exploitable" state exists. Unreachable targets never count as remediation.
3. Missing or hidden PHP detection yields "unknown", never a fabricated
   finding.
4. Rate limits (5 rps / 2 MiB / 8 redirects / 60 s total) protect the target,
   not the scanner.

## Known limitations

- Disclosure delivery is proven against Mailpit only; real SMTP relays are
  configured in `.env` but the STARTTLS path has not been exercised against
  a live relay.
- Contact fallback (MX/DNS guessing) is intentionally absent -- discovery
  uses published security contacts only.
- Single node by design: no clustering, no multi-user isolation. Do not
  expose the stack to other machines.

## License

MIT -- you own your scans. CVE-2026-109618 / CVE-2026-109619 assessment logic
is reconstructed purely from public advisory data; Sentinel never exploits,
it measures exposure.
