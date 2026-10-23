.PHONY: up down build logs migrate test lint typecheck security-check audit e2e lab-up lab-down web-install web-build

# ── Stack ────────────────────────────────────────────────────────────────────
up:            ## Build and start the full stack (web, api, worker, db, redis, mailpit)
	docker compose up --build -d
down:          ## Stop the stack
	docker compose down
build:         ## Build all images
	docker compose build
logs:          ## Tail all logs
	docker compose logs -f

# ── Database ─────────────────────────────────────────────────────────────────
migrate:
	docker compose exec api sh -c "cd /app/apps/api && alembic upgrade head"

# ── Lab ──────────────────────────────────────────────────────────────────────
lab-up:        ## Start the local PHP2Shell test lab
	docker compose --profile lab up --build -d lab-vulnerable lab-patched lab-hidden-version lab-phpinfo-enabled lab-phpinfo-disabled lab-vendor-backport
lab-down:
	docker compose --profile lab down

# ── Quality gates ────────────────────────────────────────────────────────────
test:
	python -m pytest packages/shared/tests packages/scanner/tests packages/vulnerability-db/tests apps/api/tests -q
lint:
	python -m ruff check .
typecheck:
	python -m mypy packages/shared/src packages/scanner/src packages/vulnerability-db/loader/src
security-check:
	python -m bandit -q -r apps/api/app packages/shared/src packages/scanner/src
web-install:
	cd apps/web && npm install
web-build:
	cd apps/web && npm run build
