# Sentinel — Startup & Testing Guide

Practical, copy-paste instructions for running and testing the Sentinel
vulnerability monitoring platform on this machine (Windows, PowerShell).
Everything here reflects the verified state of this repository; commands
marked **[verified]** were executed live and produced the stated output.

> This project is **local-only** by design. Do not publish it to the
> internet, and only scan hosts you own or are authorized to test.

---

## 1. Prerequisites

| Tool | Needed for | Notes |
|---|---|---|
| Docker Desktop | full stack, test labs | Start it first; a cold boot takes ~1–2 min. `docker info` must return no error before anything below works. |
| Python 3.11+ | local tests, local-dev flow | This repo uses `.venv\Scripts\python.exe` (3.12.10). |
| Node 22 | web app build / `npm audit` | `node -v` ≥ 22 (Next 16 requirement). |

Check the two local Python entrypoints exist in the venv: `celery.exe`,
`uvicorn.exe` (`Get-ChildItem .venv\Scripts -Name | Select-String "celery|uvicorn"`).

---

## 2. One-time setup

```powershell
# 1) create your env file (never commit it; it is gitignored)
Copy-Item .env.example .env
# single-user app: no secret to generate; optionally set OWNER_EMAIL in .env
```

**Port collisions (you already hit this once):** host port 8000 on this
machine is owned by the unrelated `sentinelscanner-api-1` container
(`netstat -ano | Select-String ":8000.*LISTENING"` → PID of that project).
Sentinel's compose ports are env-driven, so either:

- edit `.env` and add `API_HOST_PORT=8010` and `WEB_HOST_PORT=3005` (persistent), or
- export them per-session before `docker compose up` (shown at step 3).

With `.env` set to 8010/3005, the API is `http://127.0.0.1:8010/health`
and the web app is `http://localhost:3005`. Everything below uses
`API_HOST_PORT=8010` in examples — substitute `8000` if you freed the port.

---

## 3. Start the full stack (Docker) — primary path

```powershell
# build + start everything, including the six test labs at once
docker compose up --build -d --profile lab

# or, keeping the values out of .env:
$env:API_HOST_PORT="8010"; $env:WEB_HOST_PORT="3005"
docker compose up --build -d --profile lab
```

What comes up: `db` (Postgres 16), `redis`, `mailpit`, `api` (runs
`alembic upgrade head` then uvicorn), `worker` (celery worker **with beat**),
`web`, plus labs `lab-vulnerable`/`lab-patched`/`lab-hidden-version`/
`lab-phpinfo-enabled`/`lab-phpinfo-disabled`/`lab-vendor-backport`
(host ports 8081–8086).

### 3.1 Verify the stack is healthy **[verified]**

```powershell
docker compose ps                        # every service "healthy" or "running"
curl http://127.0.0.1:8010/health        # 200, {"status":"ok"}
curl http://127.0.0.1:8010/ready         # 200 — DB+Redis migrations checked
curl -o NUL -s -w "%{http_code}" http://localhost:3005   # 200 (web UI)
# /api proxy test through the web server itself (200 = proxy works):
curl -o NUL -s -w "%{http_code}" http://localhost:3005/api/assets
```

- Mailpit UI (fake mailbox): **http://localhost:8025** — inbox for all
  Sentinel emails; SMTP sink on `localhost:1025`.
- Worker log must show celery ready with the 6 registered tasks
  (`scan_asset`, `discover_contact`, `send_disclosure`, `send_test_email`,
  `schedule_due_scans`, `fail_stuck_scans`) and the 2 beat entries
  (`schedule-due-scans`, `sweep-stuck-scans`, 60 s cadence each):

```powershell
docker compose logs worker | Select-String "ready|registered|beat"
```

### 3.2 Stop / teardown

```powershell
docker compose --profile lab down    # stops + removes; keeps the db_data volume
docker compose --profile lab down -v # also WIPES the database (fresh start)
```

The unrelated `sentinelscanner_*` containers on this host are in their own
compose project — `down` in `C:\Projects\Sentinel` never touches them.

---

## 4. Local-dev flow (no full stack)

Run Postgres, Redis, Mailpit as plain containers and the three app processes
in the venv. Use uncommon host ports so nothing collides with either project.

```powershell
# 4.1 infra only
docker run -d --name sentinel-dev-db  -e POSTGRES_USER=sentinel -e POSTGRES_PASSWORD=sentinel -e POSTGRES_DB=sentinel -p 5433:5432 postgres:16-alpine
docker run -d --name sentinel-dev-redis -p 6380:6379 redis:7-alpine
docker run -d --name sentinel-dev-mail -p 1025:1025 -p 8025:8025 axllent/mailpit:v1.20

# 4.2 point .env at localhost (edit these lines)
#     DATABASE_URL=postgresql+psycopg2://sentinel:sentinel@localhost:5433/sentinel
#     REDIS_URL=redis://localhost:6380/0
#     SMTP_HOST=localhost   SMTP_PORT=1025

# 4.3 venv install (editable packages, same order as the Dockerfile)
& .venv\Scripts\pip.exe install -r apps\api\requirements.txt
& .venv\Scripts\pip.exe install -e packages\shared -e packages\vulnerability-db -e packages\scanner

# 4.4 migrate + run API (three shells)
cd apps\api; & ..\..\.venv\Scripts\alembic.exe upgrade head
& ..\..\.venv\Scripts\python.exe -m uvicorn app.main:app --reload --port 8000   # shell 1

# 4.5 worker (-Q explicit)
cd apps\api; & ..\..\.venv\Scripts\celery.exe -A app.workers.celery_app:celery_app worker -Q sentinel -c 2 -l INFO --beat   # shell 2

# 4.6 web dev server proxies /api + /health to localhost:8000 (next.config.mjs rewrites)
cd apps\web; npm run dev   # shell 3 → http://localhost:3000
```

Caveats for local-dev:

- Scanning a **lab** from the local-dev stack means hitting
  `http://127.0.0.1:8081` (lab-vulnerable host port), which the SSRF guard
  blocks unless `SCAN_ALLOW_PRIVATE_TARGETS=1` in `.env`. Set it, test,
  **reset it to `0` afterwards** — while it is `1` every private-target
  check is disabled.
- The vulnerability-db data path resolves from the repo layout in
  edit-installs; no extra env needed here (in Docker the image sets
  `SENTINEL_VULNDB_DATA=/data`).

---

## 5. First-run walkthrough (UI, end-to-end) **[verified]**

Use the **Docker stack** and its labs. In `.env` set
`SCAN_ALLOW_PRIVATE_TARGETS=1` and the host ports from §2 — the E2E
session used the compose DNS name for the target, exactly as below.

1. **Open the app** — `http://localhost:3005`. There is no login; the app
   opens straight to the dashboard as the single local owner.
2. **Add asset** — Assets page. Name it, URL = `http://lab-vulnerable:80`
   (lab-vulnerable is the vulnerable lab). The form will not submit until
   you tick **"I confirm I own this host…"** — the mandatory authorization
   checkbox. An asset created without it via API gets
   `409 AUTHORIZATION_REQUIRED` when scanning.
3. **Scan** — asset detail → *Scan now*. The worker executes a real,
   non-exploitative scan: detection only, no payloads, ~0.4 s on the lab.
4. **Finding appears** — CRITICAL `PHP2SHELL-2026-A`, state
   `HIGH_CONFIDENCE`, detected `8.4.26` vs fixed `8.4.27` (CVE-2026-109618,
   CVSS 9.8) with 5 evidence rows (http header, phpinfo page, version
   comparison, vendor markers, assessment note). The assessment note says
   explicitly that no exploitation was attempted.
5. **Reports** — findings page → JSON (machine, `SENTINEL-REPORT/1.0`) and
   HTML evidence report, both downloadable.
6. **Contacts** — asset page → *Discover contacts*. The lab ships a
   `security.txt` (`security@vulnerable.lab.invalid`, HIGH confidence).
   No guessing/MX available by design yet.
7. **Disclosure draft** — finding → *Prepare disclosure* (201). The note
   states no exploitation was performed.
8. **Test email first** — disclosures page → *Send test*: 202, and it goes
   to **your own account address** in Mailpit `<TEST>...` — never to the
   discovered contact.
9. **Approve & send** — the real send requires the disclosure to have been
   approved after the test email loop. Result: `DELIVERED` with the SMTP
   delivery response shown; the audit trail records every transition.
10. **Duplicate guard** — any second draft+send to the same contact for the
    same finding → `409 DUPLICATE_DISCLOSURE`.
11. **Remediation loop** — the lab version is baked into its nginx config;
    simulate the vendor fix in-place (ephemeral; a `restart lab-vulnerable`
    restores it, and `lab-patched` proves the same detection logic with
    8.4.27):

    ```powershell
    docker compose exec lab-vulnerable sh -c `
      "sed -i 's/8\.4\.26/8\.4\.27/g' /etc/nginx/conf.d/default.conf && nginx -s reload"
    ```

    *Re-scan* → the fresh evidence version `8.4.27` ≥ fixed → state becomes
    `PATCHED` → *Close* → `RESOLVED`.

**Shielded and inconclusive targets.** A target that answers with a bot
challenge (InfinityFree JS challenge, Cloudflare) scans to `COMPLETED` but
carries a **Shielded** badge and the warning "not a clean bill of health";
a target that runs PHP without disclosing the version shows
"PHP (version not disclosed)". Both are honest inconclusive results, not
passes — re-verify outside the challenge before assessing exposure.

Afterwards **restore `SCAN_ALLOW_PRIVATE_TARGETS=0`** in `.env` and restart
the api/worker.

---

## 6. Automated testing (all gates) — **[verified]**

```powershell
# backend: FastAPI suite (36 passed; sqlite; conftest forces
# SCAN_ALLOW_PRIVATE_TARGETS=1 for the in-process lab only)
cd apps\api
& C:\Projects\Sentinel\.venv\Scripts\python.exe -m pytest tests -q -p no:warnings

# packages: 72 passed (scanner 35 incl. TLS/AIA, hostname-mismatch, shield fingerprinting and stack signals; shared 33; vulnerability-db 4)
cd C:\Projects\Sentinel
& C:\Projects\Sentinel\.venv\Scripts\python.exe -m pytest packages\scanner\tests packages\shared\tests packages\vulnerability-db\tests -q -p no:warnings

# lint / types / security (back at repo root)
cd C:\Projects\Sentinel
& .venv\Scripts\python.exe -m ruff check .
& .venv\Scripts\python.exe -m mypy packages\shared\src packages\scanner\src packages\vulnerability-db\loader\src
& .venv\Scripts\pip.exe install --quiet bandit pip-audit
& .venv\Scripts\python.exe -m bandit -q -r apps\api\app packages\shared\src packages\scanner\src
& .venv\Scripts\python.exe -m pip_audit
```

Frontend (from `apps\web`):

```powershell
npm run typecheck      # tsc --noEmit, clean
npm run build          # next 16, 16 routes, clean
npm audit              # 0 vulnerabilities (fixed by the next@16 bump)
```

| Gate | Expected |
|---|---|
| API tests | 36 passed |
| Package tests | 72 passed (108 total) |
| ruff | All checks passed |
| mypy (CI scope) | no issues in 20 source files |
| bandit | 0 issues |
| pip-audit | no known vulnerabilities |
| npm audit | 0 vulnerabilities |
| web build | 18 routes generated |

CI note: the GitHub Actions workflow in `.github/workflows/ci.yml` runs the
same gates, but the first real runs on GitHub failed before executing any
step — **"your account is locked due to a billing issue"** (see
Settings → Billing on GitHub). No code change fixes that; once billing is
clear, re-run the workflow from the Actions tab — all locally-mirrored
gates currently pass.

---

## 7. Troubleshooting

| Symptom | Cause & fix |
|---|---|
| `Bind for 127.0.0.1:8000 failed: port is already allocated` | `sentinelscanner-api-1` (other project) owns the port. Set `API_HOST_PORT=8010`/`WEB_HOST_PORT=3005` in `.env`, or `docker stop sentinelscanner-api-1`. |
| **Any** UI action shows `Request failed (500)` and `web` logs show `ECONNREFUSED 127.0.0.1:8000` | The web app proxies `/api/*` from its own container — `localhost` is wrong there. The compose file now passes `NEXT_PUBLIC_API_URL=http://api:8000` **at build time** (Turbopack bakes rewrites into `routes-manifest.json`, so setting it only at runtime is not enough). If you need a custom value, set `NEXT_PUBLIC_API_URL` in `.env` before `docker compose build web`. |
| `docker compose` says daemon unreachable | Docker Desktop not running. `"C:\Program Files\Docker\Docker\Docker Desktop.exe"`; wait ~2 min, then `docker info`. |
| Asset URL rejected during lab scan (`SUSPICIOUS_HOST` / `PRIVATE_TARGET`) | You are scanning `127.0.0.1`/`lab-vulnerable` with the guard active. Use the compose DNS name from the **stack**, and `SCAN_ALLOW_PRIVATE_TARGETS=1` for anything loopback; reset to `0` when done. |
| `host.docker.internal` rejected | By design (`.internal` suffix rule) — from a stack-local scan target use the compose service DNS name (`http://lab-vulnerable:80`), the scanner and web run on that same Docker network. |
| Scan row stuck QUEUED/SCANNING forever | It should self-heal: `fail_stuck_scans` (beat, 60 s) fails anything older than `STUCK_SCANS_STALE_SECONDS` (default 900 s ≫ 60 s scan budget). Errors are `SCAN_STUCK_QUEUED` / `SCAN_STUCK` and you get an in-app notification. Set `STUCK_SCANS_ENABLED=0` to disable. |
| HTTP 500 on "queue scan" shortly after `up` | Worker still booting celery beat — wait, or restart `worker` service; check `docker compose logs worker`. |
| Writes failing after a container reset (stale browser tab) | Not possible anymore — there are no cookies/sessions. If anything 500s, check `docker compose logs api` first; hard-reload the page. |
| Mailpit inbox empty after test email | Wrong SMTP sink. Docker stack expects `SMTP_HOST=mailpit`, `SMTP_PORT=1025` (see `.env.example`); local-dev expects `SMTP_HOST=localhost`. Browse http://localhost:8025 and check `docker compose logs worker` for the SMTP error. |
| Scan fails with `CERTIFICATE_VERIFY_FAILED — unable to get local issuer certificate` | The target serves an incomplete TLS chain (leaf only, no intermediates — common on misconfigured hosts). Sentinel never bypasses verification; instead the missing intermediate is appended to `infra/tls/ca-bundle.pem` (system roots + intermediates, certificate data only) which api+worker load via `SSL_CERT_FILE=/certs/ca-bundle.pem` (compose anchors `x-tls-bundle`/`x-tls-mount`). To trust a new chain: save the missing intermediate as PEM, append it to the bundle, then `docker compose restart api worker`. Verify in-container with `docker compose exec api python -c "import httpx; print(httpx.get('https://<host>', timeout=15).status_code)"`. |
| Scan of `https://www.example.YOURDOMAIN/…` fails with hostname mismatch | Wildcard certs cover ONE label. `www.exams.domain` needs `*.exams.domain`, but the cert has `*.domain`. Use the bare host without the extra `www.` when the wildcard scope is the parent domain. (Verified live 2026-10-24 on keralauniversity; scan error code `TLS_CERT_HOSTNAME_MISMATCH`.) |
| Deleting an asset throws "An internal error occurred." (500) | **Fixed** (was: `Finding.disclosures` lacked an ORM cascade → SQLAlchemy nulled the NOT NULL `disclosures.finding_id`). If you still see it, rebuild backend images: `docker compose up -d --build api worker`. |
| Discover button did nothing (2 clicks, no feedback) | **Fixed** in the redesign: discover POSTs immediately with an per-second-ish poll (~12 s) until the async job finishes, and errors now surface with friendly wording (`onError` was missing before). |
| A page shows "This page couldn't load" after a deploy | Firefox/dev tools console will show a hydration mismatch — React 19 treats any SSR/CSR difference as fatal. Sentinel avoids wall-clock output during SSR (client-only `<NowStamp />` component); don't reintroduce `new Date()`/`toLocale*` in server components. |
| Duplicate assets (same URL re-added) | Known gap (no unique tuple), not harmful; the duplicate guard blocks an identical disclosure instead. Delete the extras on the Assets page. |

---

## 8. Honest status caveats (before you rely on it)

1. **Single-user, no login.** Auth/sessions/CSRF were removed deliberately so
   anyone with loopback access (i.e. the local machine) is the owner. Do not
   expose the services to other machines.
2. **Real SMTP is unverified.** The disclosed-email path is fully proven
   against Mailpit only (behaviour identical API+worker-side; real relay
   needs your own credentials in `.env`, set `SMTP_TLS=1` for 587/
   STARTTLS relays).
3. **CI is not green yet** — blocked by the GitHub account "billing lock"
   described in §6; fix at Settings → Billing and re-run.
4. Frontend has **zero automated tests** (typecheck/build only).
5. `npm audit` on current Next 16 = 0 vulnerabilities; do not pin back to
   `next@15` (it reintroduces advisories).
6. **TLS trust is strengthened, never bypassed.** api/worker load
   `infra/tls/ca-bundle.pem` (public certs only) via `SSL_CERT_FILE`; the
   scanner auto-fetches missing intermediates via AIA (RFC 5280) and still
   returns `TLS_CERT_CHAIN_INCOMPLETE` when the chain cannot be completed —
   there is no code path that disables certificate verification.
7. Current status, limitations, and quick reference: the README.md
   sections (Security design / Known limitations / Testing).
