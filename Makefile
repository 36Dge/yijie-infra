.PHONY: dev-up dev-down dev-status lint test plan apply deploy rollback

dev-up:
	docker compose -f docker-compose.local.yml up -d --wait

dev-down:
	docker compose -f docker-compose.local.yml down

dev-status:
	docker compose -f docker-compose.local.yml ps

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
