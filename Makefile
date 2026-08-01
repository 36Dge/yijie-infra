.PHONY: dev-up dev-down dev-status feat-125-nonprod-template feat-125-nonprod-ready feat-125-nonprod-online lint test plan apply deploy rollback

dev-up:
	docker compose -f docker-compose.local.yml up -d --wait

dev-down:
	docker compose -f docker-compose.local.yml down

dev-status:
	docker compose -f docker-compose.local.yml ps

feat-125-nonprod-template:
	pnpm validate:feat-125-template

feat-125-nonprod-ready:
	@test -n "$(CONFIG)" || (echo "CONFIG is required" >&2; exit 2)
	node scripts/validate-feat-125-nonprod.mjs --mode ready "$(CONFIG)"

feat-125-nonprod-online:
	@test -n "$(CONFIG)" || (echo "CONFIG is required" >&2; exit 2)
	node scripts/validate-feat-125-nonprod.mjs --mode ready --online "$(CONFIG)"

lint:
	./scripts/plan.sh

test:
	pnpm test
	./scripts/plan.sh

plan:
	./scripts/plan.sh

apply:
	./scripts/apply.sh

deploy:
	./scripts/deploy.sh

rollback:
	./scripts/rollback.sh
