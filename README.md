# 🛡 Sentinel

**Authorized web vulnerability monitoring — detect, verify, explain, disclose.**

Sentinel is a local-first, full-stack security monitoring platform. You register the
sites you own or are authorized to test, Sentinel scans them with a strictly
**non-invasive** revolution-engine (no payloads, no exploits), verifies PHP
exposure against the **PHP2Shell vulnerability intelligence** (CVE-2026-109618 /
CVE-2026-109619), discovers the responsible disclosure contact, drafts the
responsible-disclosure email for **your** approval, and tracks the finding to
**PATCHED** after you fix and re-verify.

> ⚠️ **Ethics & scope** — Sentinel intentionally never exploits anything. A remote
> scanner can never claim more than `HIGH_CONFIDENCE`. Only scan infrastructure
> you own or have written permission to test.

---

## Table of contents

- [Features](#-features)
- [Architecture](#-architecture)
- [Project structure](#-project-structure)
- [Core logic walkthrough](#-core-logic-walkthrough)
- [Finding lifecycle & severity policy](#-finding-lifecycle--severity-policy)
- [Responsible disclosure engine](#-responsible-disclosure-engine)
- [Security design](#-security-design)
- [Quick start (Docker)](#-quick-start-docker)
- [Quick start (no Docker, dev mode)](#-quick-start-no-docker-dev-mode)
- [How to test](#-how-to-test)
  - [1. Automated test suites](#1-automated-test-suites)
  - [2. Quality gates](#2-quality-gates)
  - [3. Full manual E2E walkthrough (lab + Mailpit)](#3-full-manual-e2e-walkthrough-lab--mailpit)
  - [4. The six lab scenarios](#4-the-six-lab-scenarios)
- [API surface (summary)](#-api-surface-summary)
- [Frontend pages](#-frontend-pages)
- [Environment variables](#-environment-variables)
- [Design decisions & honestness](#-design-decisions--honestness)

---

## ✦ Features

| Area | What it does |
|---|---|
| **Asset management** | Register targets with SSRF-guarded URL normalization, authorization confirmation, monitoring intervals |
| **PHP detection** | `X-Powered-By` header, `Server` header, phpinfo page scraping, HTML body markers, vendor/distro markers, redirect hops — even behind hidden/exotic configurations |
| **PHP2Shell assessment** | Safe risk assessment of CVE-2026-109618 & CVE-2026-109619 (version comparison model only) |
| **Evidence gathering** | Timestamped, versioned evidence rows (headers, version comparisons, assessment notices) |
| **Contact discovery** | `/.well-known/security.txt`, `/security.txt`, HTML meta/link scanning — no probing beyond what a visibility scanner does |
| **Disclosure engine** | Draft → edit → test email → mark pending → approve → send (Mailpit/SMTP), duplicate protection, cancellation |
| **Remediation verification** | "Verify fix" re-scan marks a finding `PATCHED` only when fresh evidence proves the new version ≥ fixed release |
| **Reports** | JSON + HTML vulnerability reports with non-exploitation statements, plus browser PDF export |
| **Dashboards** | Grouped sidebar (Overview/Monitoring/Security/Disclosure/System) with live unread/open-finding badges, 14-day trends from real scans, posture score, severity overview, audit trail |
| **Test lab** | Six nginx-based local PHP2Shell scenarios (see [lab section](#4-the-six-lab-scenarios)) |

---

## ✦ Architecture

```
┌──────────────┐     cookies + CSRF      ┌──────────────┐   Celery   ┌──────────────┐
│   Next.js    │ ──────────────────────▶ │   FastAPI    │ ─────────▶ │ Celery worker│
│   (web:3000) │ ◀────────────────────── │   (api:8000) │            │ scan/contact │
│  TanStack Q  │     JSON envelopes      │  AUTX/CSRF/  │            │ disclosure   │
└──────────────┘                         │  ratelimit   │            │ scheduler    │
                                         └──────┬───────┘            └──────┬───────┘
                                                │                           │
                                ┌───────────────┼───────────────┐           │
                                ▼               ▼               ▼           ▼
                          ┌──────────┐  ┌──────────────┐  ┌──────────┐  ┌──────────┐
                          │PostgreSQL│  │    Redis     │  │  Mailpit │  │ Sentinel │
                          │ (db:5432)│  │ (redis:6379) │  │(mail:1025│  │ Scanner  │
                          │  schema  │  │  broker+kv   │  │ UI: 8025 │  │ packages │
                          └──────────┘  └──────────────┘  └──────────┘  └──────────┘
```

- **apps/web** — Next.js 16 (App Router) + Tailwind v4 + TanStack Query +
  lucide-react icons. Dark SaaS security-dashboard UI; talks to the API via a
  next.config rewrite proxy so cookies stay same-origin.
- **apps/api** — FastAPI + SQLAlchemy 2.0 + Alembic + Celery + Argon2id sessions.
- **packages/shared** (`sentinel_shared`) — SSRF URL-guard, versioning,
  header redaction (used by BOTH API and scanner).
- **packages/vulnerability-db** (`sentinel_vulndb`) — CVE intelligence loading
  (`data/php2shell.json`).
- **packages/scanner** (`sentinel_scanner`) — detection, fingerprinting, risk
  assessment, evidence collection.
- **tests/labs** — six Dockerized vulnerable/patched/hidden-vendor lab scenarios.
- **Mailpit** — dev SMTP catcher; disclosure emails land at http://localhost:8025.

---

## ✦ Project structure

```
Sentinel/
├── apps
│  ├── api/                        FastAPI service
│  │  ├── app/
│  │  │  ├── main.py               app factory, health/ready, security headers, error envelope
│  │  │  ├── core/                 config, db, security (Argon2id+sessions), rate_limit, logging
│  │  │  ├── models.py             SQLAlchemy models (GUID primary keys)
│  │  │  ├── schemas/v1.py         Pydantic v2 schemas (validation + enums)
│  │  │  ├── api/                  deps (auth/CSRF) + routers (assets, scans, findings, …)
│  │  │  ├── services/             scan_exec, contact_exec, disclosure_exec, reports, email, audit
│  │  │  └── workers/              celery app + tasks + beat scheduler
│  │  ├── alembic/                 migrations (a481839888c5 initial schema)
│  │  └── tests/                   25-test integration suite (sqlite, lab stub)
│  └── web/                        Next.js 15 frontend (hand-written, no create-next-app)
│     ├── app/                     (root page, login, (app)/ protected pages)
│     ├── components/              ui.tsx primitives + badges/page/chart/metrics/nav systems
│     ├── hooks/use-session.ts     session/login/register/logout hooks
│     └── lib/                     api.ts typed fetch client, types.ts models, format.ts formatters
├── packages/
│  ├── shared/                     sentinel_shared: urlguard SSRF, versioning, redaction
│  ├── vulnerability-db/           sentinel_vulndb: data/php2shell.json + loader
│  └── scanner/                    sentinel_scanner: http client, detectors, risk, evidence
├── tests/labs/php2shell/          6 lab targets (nginx, one scenario each)
├── infra/docker/                  api.Dockerfile + web.Dockerfile
├── docker-compose.yml             full stack (+ profile: lab)
├── .github/workflows/ci.yml       lint/typecheck/tests/docker builds
└── Makefile                       up/down/test/lint/typecheck/web-*
```

---

## ✦ Core logic walkthrough

### 1. URL & SSRF guard (`packages/shared/src/sentinel_shared/urlguard.py`)
Before an asset exists and before **every scanned request hop**:
- rejects non-http(s), userinfo URLs (user:pass@host), bad ports, invalid chars;
- resolves host via `socket.getaddrinfo` with all-or-nothing policy: **if any
  resolved address is private/reserved, host is rejected** — defeats
  partially-rebinding DNS;
- blocks decimal/integer representations (`http://2130706433/`), metadata IPs,
  IPv6 forms, look-alike hosts;
- `SCAN_ALLOW_PRIVATE_TARGETS=1` allows local labs to run (development only).

The scanner executes this check again **per hop** after every redirect — safe by
construction even against adversarial targets.

### 2. PHP fingerprinting (`packages/scanner/…/detectors/php.py`)
Runs on every response (base, redirects, sub-paths):
- `X-Powered-By: PHP/x.y.z` (header),
- `Server: Apache/2.4.x (Unix) PHP/8.4.26 mod_…` text,
- `/phpinfo.php` presence + `PHP Version x.y.z` content extraction,
- page-body markers (e.g., PHP version in HTML),
- vendor/distro markers (backport/distro-version strings, e.g. `+dist-backport1`).

Detection results are ranked: `header disclosure` > `body/phpinfo` > `inferred`.

### 3. PHP2Shell risk assessment (`packages/scanner/…/risk/php2shell.py`)
Puresafe version-comparison logic — **no payloads**:
- loads all CVEs from `data/php2shell.json`
- compares detected version against `fixed_in` for each CVE using
  `packaging.version.Version` (correct 8.4.26 < 8.4.27 semantics)
- emits a Finding record with: severity, CVSS, `summary`, `impact`,
  `remediation`, `fixed_version`, references, evidence items (header snapshot,
  version comparison string, **non-invasive assessment notice**).

CVEs covered (`packages/vulnerability-db/data/php2shell.json`):

| ID | CVE | Severity | CVSS | Fixed versions | Vendor backport note |
|---|---|---|---|---|---|
| `PHP2SHELL-2026-A` | CVE-2026-109618 | CRITICAL | 9.8 | 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12 | applies |
| `PHP2SHELL-2026-B` | CVE-2026-109619 | (grouped with A) | — | same | applies |

### 4. Scan pipeline (`packages/scanner/…/evidence/scan.py` → api `services/scan_exec.py`)
1. API queues scan, Celery worker (`app/workers/tasks.py: scan_asset`) picks it up.
2. `execute_scan` (DB side) calls the scanner **synchronously with a hard budget**:
   SSRF-validated URL, bounded redirects (8 max), bounded body (2 MiB), rate
   limit (5 req/s), concurrency 4, user-agent `SentinelSecurityScanner/1.0.0`.
3. Resulting evidence is transformed to DB rows:
   - `assessment_notice` — text explicitly says **no exploitation was performed**;
   - finding dedup by `vulnerability_id` per asset (no duplicate rows across runs);
   - notifications + audit log rows on `SCAN_QUEUED`, `SCAN_COMPLETED`,
     `FINDING_OPENED`, `FINDING_RUNNING`, `FAILURE` paths.

### 5. Contact discovery (`packages/scanner` + api `services/contact_exec.py`)
Fetches only these, without probing deeper paths:
- `/.well-known/security.txt` (RFC 9116 semantics) — parsed `Contact:`/
  `Policy:`/`Encryption:`/`Preferred-Languages:` fields,
- `/security.txt` (legacy spot-check),
- HTML `<meta name="security-contact">` / `mailto:`/link scanning of the
  homepage one hop deep.

Discovery writes `disclosure_contacts` rows with a confidence label
(`HIGH`/`MEDIUM`/`LOW` depending on the source). No sending happens automatically.

### 6. Remediation verification (`apps/api/…/services/scan_exec.py`)
`POST /api/findings/{id}/verify-fix` queues a **fresh** scan against that asset:
- if the new scan no longer detects the vulnerability **AND** the new scan's own
  PHP evidence (fresh version, not the stale one) is `>= fixed_in`,
  the finding is marked `PATCHED` and closed;
- unreachable targets **never** count as remediation;
- `POST /api/findings/{id}/rescan` / `close` work together with the schedule.

---

## ✦ Finding lifecycle & severity policy

**Severity is honest by design:** remote non-invasive data can only *ever* lead
to:

```
NOT_DETECTED ─◀─ scan misses
HIGH_CONFIDENCE ─ feasible remote evidence matches the CVE exactly (the ceiling
LIKELY_VULNERABLE ─ additional distro/vendor backport markers observed
PATCHED ───────── resolve path: verified with fresh version evidence
```

No `EXPLOITED`/`VERIFIED_EXPLOITABLE` state exists anywhere in the codebase.

Finding avidity fields: `severity` (CRITICAL/HIGH/MEDIUM/LOW), `cvss`,
`confidence`, `status` (user-side RESOLVED etc.), `state` (scanner-side above),
`detected_version`, `fixed_version`, `detection_method`.

---

## ✦ Responsible disclosure engine

The 6-step state machine is protected by explicit transitions and checks:

```
   ┌ (no contact yet) → 409 NO_CONTACT
DRAFT ─edit→ DRAFT ─test-email→ sends to YOUR OWN address
   └─mark-pending→ PENDING_APPROVAL ─approve→ APPROVED (queued) → SENT → DELIVERED
                                  └─cancel→ CANCELLED
DELIVERED/SENT ─ send again (resend) ─→ duplicated? no — explicit resend only
                                   ─→ 409 DUPLICATE_DISCLOSURE for same finding+recipient
```

Guarantees:
- nothing sends without explicit `approve` (or `send-now` for resend);
- test emails never go to the vendor — they go to your own account address;
- recipients come **only** from contacts previously discovered on the asset;
- SMTP uses the bundled Mailpit receiver by default;
- the draft follows a professional structure (vulnerability/severity/host →
  observed evidence → security impact → **Testing Performed**, stating
  explicitly that no exploitation was performed and no RCE payload was
  executed → recommended remediation → references → good-faith closing →
  `Regards,` + sender name derived from your account email); the body stays
  editable before sending;
- subject/body are redaction-checked; sweeping "we will publish in X days"
  templates are avoided — the template keeps an amicable professional tone.

---

## ✦ Security design

| Concern | Implementation |
|---|---|
| Passwords | Argon2id (argon2-cffi), 12+ char, upper+lower+digit validated |
| Sessions | Opaque random tokens, **hashed-at-rest** in `sessions`, DB row TTL, HttpOnly cookie `sentinel_session` (Secure when COOKIE_SECURE=1) |
| CSRF | Double-submit cookie `sentinel_csrf` (JS-readable) + `x-csrf-token` header checked on every mutating endpoint via router-level `require_csrf` |
| Rate limiting | Per-IP + per-user Redis sliding windows, fail-open on Redis outage, `429` + `Retry-After` |
| SSRF | Full resolve-then-connect guard, per-hop revalidation, decimal/IP evasion blocked, metadata ranges blocked |
| Secrets | Headers redacted in evidence, exceptions log type-only (`Argon2Error`), errors return `{"error":{"code","message"}}` — no stack traces |
| Response hardening | `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, `Permissions-Policy`, `Server: sentinel` |
| Audit | Every security-relevant action logged (`SCAN_QUEUED`, `FINDING_OPENED`, `DISCLOSURE_SENT`, …) |
| Object ownership | every route filters by `user_id`, unseen objects behave as 404s |

---

## ✦ Quick start (Docker)

```powershell
# 1. Configure
Copy-Item .env.example .env
# edit .env → set a real SESSION_SECRET (docker compose uses the file)

# 2. Full stack: web + api + worker + db + redis + mailpit
docker compose up --build -d
docker compose logs -f   # wait for "ready"

# 3. App is available at:
#    Web      → http://localhost:3000
#    API docs → http://localhost:8000/docs
#    Mail UI  → http://localhost:8025 (Mailpit, all disclosures land here)
```

The API container runs `alembic upgrade head` on boot against Postgres.

**Test lab** (separate profile to avoid scanning production-like targets):

```powershell
docker compose --profile lab up --build -d lab-vulnerable lab-patched
# vulnerable → http://localhost:8081
# patched    → http://localhost:8082
# ... + 4 more scenarios (see table below)
```

> `SCAN_ALLOW_PRIVATE_TARGETS=1` in `.env` is required to scan the lab
> containers (they live on the docker 172.16/ private interface and do not
> resolve public DNS). Set `SCAN_ALLOW_PRIVATE_TARGETS=0` again for
> internet-visible scanning.

---

## ✦ Quick start (no Docker, dev mode)

Requires: Python 3.12, Node 22, a Postgres 16 and Redis 7 (or reuse Docker for
just those services: `docker compose up -d db redis mailpit`).

```powershell
# Python side
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install ./packages/shared ./packages/vulnerability-db ./packages/scanner
pip install -r apps/api/requirements.txt
cd apps/api
alembic upgrade head
uvicorn app.main:app --reload --port 8000
# in another PowerShell: celery -A app.workers.celery_app:celery_app worker --loglevel=INFO
```

```powershell
# Frontend side (separate PowerShell)
cd apps/web
npm install
npm run dev         # → http://localhost:3000 (proxy → :8000)
```

---

## ✦ How to test

### 1. Automated test suites

| Suite | Command | Count | What's covered |
|---|---|---|---|
| Shared package | `python -m pytest packages/shared/tests -q` | ~40 | ALL SSRF-relevant branches: loopback, RFC1918, 169.254.169.254, decimal, hex/octal, IPv6 mapped, userinfo, bad scheme, bad port; version comparison; header redaction |
| Scanner package | `python -m pytest packages/scanner/tests -q` | ~16 | detector branches, risk assessor, Evidence transformer, HTTP client wrap-up, redirect cap |
| Vulnerability DB | `python -m pytest packages/vulnerability-db/tests -q` | ~8 | JSON integrity, CVE grouping, dedup |
| Combined packages | `python -m pytest packages -q` | **56** | all of the above |
| API integration | `cd apps/api; python -m pytest tests -q` | **25** | register/login/CSRF failures, SSRF-asset creation, scan lifecycle (201/queued→completed→finding+evidence), dedup, verify-fix→PATCHED→close, IDOR cross-user, contact discovery, full disclosure flow (DRAFT→PENDING→test email to self→APPROVED→sent), duplicates 409, reports JSON/HTML shape, notifications, audit log |

### 2. Quality gates

```powershell
python -m ruff check .                                          # 0 errors
python -m mypy packages/shared/src packages/vulnerability-db/loader/src packages/scanner/src  # 0 issues
python -m mypy apps/api                                         # annotation-checked
python -m bandit -q -r apps/api/app packages/shared/src packages/scanner/src
cd apps/web && npx tsc --noEmit && npm run build                 # clean Next.js build
```

CI (`.github/workflows/ci.yml`) runs all of this on every push/PR.

### 3. Full manual E2E walkthrough (lab + Mailpit)

**Prerequisites:** full stack `docker compose up --build -d` **or** local dev
mode + lab profile up.

1. **Sign up** at http://localhost:3000 (`/login` → register tab, any
   `name@example.com`, 12+ char password with upper/lower/digit).
2. **Add asset** → `http://localhost:8081` (the vulnerable lab) → name it
   `PHP demo`. The SSRF guard must allow this because
   `SCAN_ALLOW_PRIVATE_TARGETS=1` is set in `.env` for lab testing.
3. **Scan now** → redirect to asset detail → wait for `COMPLETED` (the worker
   picks it up within seconds). You'll see:
   - a `CRITICAL` PHP2Shell finding, CVSS 9.8, version `8.4.26`, fixed `8.4.27`;
   - evidence rows: `X-Powered-By` snapshot, version-comparison line,
     **assessment notice** (no exploitation note).
4. **Discover contacts** on the asset → finds
   `security@vulnerable.lab.invalid` from `/.well-known/security.txt`
   (confidence HIGH).
5. **Prepare disclosure** from the finding page → draft opens. Press
   **Send test email** → check http://localhost:8025 — the test lands in your
   own mailbox (never the vendor's).
6. **Mark pending → Approve & send** → status `DELIVERED`; the second
   Mailpit message shows the vendor recipient. The final email contains the
   non-exploitation statement and the version-comparison evidence (no payloads).
7. **Verify remediation** — point the scan at the *patched* lab
   (`http://localhost:8082` — same asset flow, or edit the asset URL) and run
   **Verify fix** → the finding flips to `PATCHED`, becomes closable, and
   disappears from the open count.

### 4. The six lab scenarios

| Lab | Port | Header/behaviour | Expected result |
|---|---|---|---|
| `vulnerable` | 8081 | `X-Powered-By: PHP/8.4.26`, live `/phpinfo.php`, security.txt | **CRITICAL** finding |
| `patched` | 8082 | `X-Powered-By: PHP/8.4.27`, live `/phpinfo.php`, security.txt | **no finding / PATCHED** |
| `hidden-version` | 8083 | `X-Powered-By: PHP` (no version), no phpinfo | PHP detected, version unknown → **no verdict** (honest unknown) |
| `phpinfo-enabled` | 8084 | no X-Powered-By, `/phpinfo.php` exposes 8.4.26 | **CRITICAL** via phpinfo path |
| `phpinfo-disabled` | 8085 | `X-Powered-By: PHP`, no phpinfo | Same as hidden-version |
| `vendor-backport` | 8086 | `X-Powered-By: PHP/8.4.26+dist-backport1`, `Server: dist-nginx-backport/1.0` | **LIKELY_VULNERABLE** (vendor/distro marker observed) |

---

## ✦ API surface (summary)

Interactive docs: `http://localhost:8000/docs`. Everything authenticates with
the `sentinel_session` cookie **or** a `Bearer` token, and every mutating
endpoint requires the `x-csrf-token` header matching the `sentinel_csrf` cookie.

| Route | What it does |
|---|---|
| `POST /api/auth/register` / `login` / `logout`, `GET /api/auth/me` | Session lifecycle |
| `GET/POST /api/assets`, `GET/PATCH/DELETE /api/assets/{id}` | Assets (URL guard on create) |
| `POST /api/assets/{id}/scan`, `GET /api/assets/{id}/scans` | Queue a scan / history |
| `POST /api/assets/{id}/contacts/discover`, `GET /api/assets/{id}/contacts` | Contact workflow |
| `GET /api/scans`, `GET /api/scans/{id}`, `POST /api/scans/{id}/cancel` | Scan management |
| `GET /api/scan/{id}/findings` | Results for one scan |
| `GET /api/findings`, `GET /api/findings/{id}` (with evidence + disclosures) | Findings |
| `POST /api/findings/{id}/rescan`, `POST /api/findings/{id}/close` | Finding ops |
| `GET /api/disclosures`, `GET /api/disclosures/{id}`, `PATCH /api/disclosures/{id}` | Email lifecycle |
| `POST /api/disclosures/{id}/mark-pending` / `test-email` / `approve` / `send-now` / `cancel` | State transitions |
| `POST /api/findings/{id}/disclosure` | Create a draft (requires contact first → else `409 NO_CONTACT`) |
| `GET /api/reports`, `GET /api/reports/findings/{id}.json` / `.html` | Reports |
| `GET /api/notifications` (+`/unread-count`, `/read`) | Notification centre |
| `GET /api/audit` | Audit trail |
| `GET /api/metrics/summary` | Dashboard aggregation |
| `GET /health`, `GET /ready` | Liveness/readiness (db + redis) |

All errors are consistent:
`{"error": {"code": "...", "message": "..."}}` — codes include `UNAUTHENTICATED`,
`CSRF_INVALID`, `RATE_LIMITED`, `AUTHORIZATION_REQUIRED`, `SCAN_ALREADY_RUNNING`,
`NO_CONTACT`, `DUPLICATE_DISCLOSURE`, `INVALID_TRANSITION`, `EMAIL_TAKEN`,
`INVALID_CREDENTIALS`, `PRIVATE_TARGET`, `METADATA_ENDPOINT`.

---

## ✦ Frontend pages

| Page | Route | Purpose |
|---|---|---|
| Login/Signup | `/login` | dual-mode auth, strict password rules surfaced |
| Redirect | `/` | auto routes to dashboard or login |
| **Dashboard** | `/dashboard` | assets/open-findings/resolved counters, CRITICAL spotlight, 14-day scan+finding activity chart, recent findings/scans, posture score |
| Assets | `/assets` | create (SSRF-guarded `/assets/new`), scan now / delete, live last-scan badges |
| Asset detail | `/assets/[id]` | scans timeline, contact discovery with live progress polling, authorization badge, monitoring summary |
| Findings | `/findings` | URL-param filters (severity/status/confidence/asset), PATCHED states |
| Finding detail | `/findings/[id]` | evidence cards, version strip, "Prepare disclosure", "Verify fix", "Close finding" actions |
| Vulnerabilities | `/vulnerabilities` | all targets grouped by `vulnerability_id` |
| Disclosures | `/disclosures` | all drafts — status lifecycle legend |
| Disclosure detail | `/disclosures/[id]` | edit / test email / mark-pending / approve / send-again / cancel, workflow rail, full body preview |
| Contacts | `/contacts` | all discovered contacts with confidence + related asset |
| Scans | `/scans` | filterable scan history, cancel, friendly scan errors |
| Reports | `/reports` | JSON + HTML downloads, **PDF export** (browser print pipeline) |
| Notifications | `/notifications` | unread badges + mark-read |
| Audit | `/audit` | security-relevant action trail |
| Settings | `/settings` | change password (revokes all sessions) |

The API calls are typed (`lib/api.ts` + `lib/types.ts`) via a fetch wrapper that
attaches CSRF headers and unpacks error envelopes into friendly messages.

---

## ✦ Environment variables

| Variable | Default | Meaning |
|---|---|---|
| `DATABASE_URL` | from `.env` | Postgres DSN (`sqlite` accepted in tests only) |
| `REDIS_URL` | `redis://redis:6379/0` | Celery + rate limiter backend |
| `POSTGRES_*` | `sentinel/sentinel/sentinel` | Compose DB credentials |
| `SESSION_SECRET` | **must set** | Argon2 cookie secret (pepper) |
| `SESSION_TTL_DAYS` | `14` | Session expiry |
| `COOKIE_SECURE` | `0` | Set to `1` behind HTTPS |
| `CORS_ORIGINS` | `http://localhost:3000` | Comma-separated allowed origins |
| `SMTP_HOST/PORT/USERNAME/PASSWORD/TLS`, `SMTP_FROM` | Mailpit defaults | Outbound email |
| `SCANNER_USER_AGENT` | `SentinelSecurityScanner/1.0.0` | Identifies Sentinel requests |
| `SSL_CERT_FILE` (compose) | `/certs/ca-bundle.pem` | api+worker CA bundle mount (`infra/tls/ca-bundle.pem`, public certs only) — add intermediates there for incomplete-chain targets; verification is never disabled |
| `SCAN_TIMEOUT` / `SCAN_CONNECT_TIMEOUT` / `SCAN_READ_TIMEOUT` | 60/10/30 | Transport budgets (s) |
| `SCAN_MAX_REDIRECTS` | `8` | HTTP redirect cap |
| `SCAN_MAX_RESPONSE_SIZE` | `2097152` | Per-response byte cap (2 MiB) |
| `SCAN_RATE_LIMIT` / `SCAN_CONCURRENCY` | `5.0` / `4` | rps cap / parallel fetches |
| `SCAN_ALLOW_PRIVATE_TARGETS` | `0` | **Danger toggle!!! Only for lab testing** |
| `NEXT_PUBLIC_API_URL` | `http://localhost:8000` | Web → API rewrite target |

Full reference + copy/paste template: [`.env.example`](.env.example).

---

## ✦ Design decisions & honestness

1. **No exploit payloads — ever.** The scanner's HTTP client cannot carry a
   `payload` parameter. Risk assessment is purely version math; evidence is
   uppercase statements of observation.
2. **`HIGH_CONFIDENCE` is the remote ceiling.** No "confirmed exploitable"
   state exists anywhere. Only verified version-delta evidence can mark
   `PATCHED`; unreachable targets never flip state.
3. **Fail-safe: missing/disabled PHP detection yields "unknown", not a finding.**
4. **Rate limits protect the target.** 5 rps / 2 MiB / 8 redirects / 60 s total
   budget per scan, hard.
5. **Honest negative results.** If a scan completes but PHP is absent, the scan
   records that (finding nothing is still useful reporting).
6. **Fail-open rate limiter** — if Redis is down Sentinel remains usable;
   audit/notifications keep working through the DB.
7. **Consistent 404-ownership.** Cross-user object access returns `404` and the
   audit trail records the denial, instead of leaking existence.

---

## Credits

- CVE-2026-109618 / CVE-2026-109619 assessment logic: reconstructed purely from
  public advisory data — Sentinel never exploits; it measures exposure.
- Local SVG-less logo, everything runs offline; no telemetry, no data sharing.

**License:** MIT (you own your scans).
