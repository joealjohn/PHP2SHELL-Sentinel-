# Security Policy

Sentinel is a **local, single-tenant, authorized-testing tool**. This policy
describes how we handle vulnerabilities *in Sentinel itself*, plus the rules
every operator must follow when using it.

## Supported scope

- `apps/api` — FastAPI backend
- `apps/web` — Next.js frontend
- `packages/shared`, `packages/scanner`, `packages/vulnerability-db`
- `tests/labs/**` — lab nginx configurations
- `infra/docker/**`, `docker-compose.yml`, `.github/workflows/ci.yml`

## Reporting a vulnerability in Sentinel

1. **Do not open a public issue** for anything you suspect could be exploited
   to hurt users or this tool.
2. Email `security@sentinel.local.subject` — see the contact in
   `/.well-known/security.txt` at the repo root if you self-host.
3. Include: description, minimal steps, affected commit hash, and (if possible)
   a safe reproduction on the bundled test lab. **Never** include working
   exploits that harm third parties.
4. We acknowledge within 7 days, decide within 14 on severity, and coordinate
   public disclosure.

## Rules for using Sentinel

- Only scan systems **you own or have written authorization to test**.
- Never publish, forward, or enable `SCAN_ALLOW_PRIVATE_TARGETS=1` outside of
  an isolated docker lab (it disables SSRF augmented guarding).
- Do not run Sentinel against hosts that have requested exclusion.
- Disclosure emails composed with Sentinel require your explicit `approve` —
  never send a disclosure without the asset owner's awareness.

## Hard guarantees in the code

- No payload injection or exploit execution — scanner HTTP method can never
  call an actual exploitation module.
- Finding state machine has no `CONFIRMED_EXPLOITABLE` values.
- Session token hashing at rest; CSRF-token double-submit on every mutation.
- Audit trail of every scan, draft, and disclosure send.
