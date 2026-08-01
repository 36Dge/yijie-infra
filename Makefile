.PHONY: dev-up dev-down dev-status feat-125-nonprod-template feat-125-nonprod-ready feat-125-nonprod-online feat-125-local-template feat-125-local-worktree-reference feat-125-local-init-secrets feat-125-local-up feat-125-local-stop feat-125-local-status feat-125-local-provision-users feat-125-local-api-db feat-125-local-prepare feat-125-local-trust-ca feat-125-local-ca-status feat-125-local-untrust-ca feat-125-local-ready feat-125-local-online feat-125-s7-bearer-matrix lint test plan apply deploy rollback

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

feat-125-local-template:
	pnpm validate:feat-125-local-template

feat-125-local-worktree-reference:
	@test -n "$(REPO)" || (echo "REPO is required" >&2; exit 2)
	node scripts/feat-125-worktree-evidence.mjs "$(REPO)"

feat-125-local-init-secrets:
	./scripts/init-feat-125-local-secrets.sh

feat-125-local-up:
	./scripts/feat-125-local-compose.sh up

feat-125-local-stop:
	./scripts/feat-125-local-compose.sh stop

feat-125-local-status:
	./scripts/feat-125-local-compose.sh status

feat-125-local-provision-users:
	NODE_EXTRA_CA_CERTS="$(CURDIR)/environments/local/generated/feat-125-caddy-root.crt" \
		node scripts/feat-125-local-provision.mjs

feat-125-local-api-db:
	./scripts/prepare-feat-125-local-api-db.sh

feat-125-local-prepare:
	@test -n "$(API_REF)$(API_SHA)" || (echo "API_REF or API_SHA is required" >&2; exit 2)
	@test -n "$(DESKTOP_REF)$(DESKTOP_SHA)" || (echo "DESKTOP_REF or DESKTOP_SHA is required" >&2; exit 2)
	./scripts/feat-125-local-compose.sh export-ca
	node scripts/render-feat-125-local-config.mjs \
		"$(if $(API_REF),$(API_REF),commit:$(API_SHA))" \
		"$(if $(DESKTOP_REF),$(DESKTOP_REF),commit:$(DESKTOP_SHA))"

feat-125-local-trust-ca:
	./scripts/feat-125-local-ca-trust-macos.sh install

feat-125-local-ca-status:
	./scripts/feat-125-local-ca-trust-macos.sh status

feat-125-local-untrust-ca:
	./scripts/feat-125-local-ca-trust-macos.sh remove

feat-125-local-ready:
	@test -n "$(CONFIG)" || (echo "CONFIG is required" >&2; exit 2)
	@test -n "$(API_REF)$(API_SHA)" || (echo "API_REF or API_SHA is required" >&2; exit 2)
	@test -n "$(DESKTOP_REF)$(DESKTOP_SHA)" || (echo "DESKTOP_REF or DESKTOP_SHA is required" >&2; exit 2)
	node scripts/validate-feat-125-local.mjs --mode local-lab \
		--expected-api-reference "$(if $(API_REF),$(API_REF),commit:$(API_SHA))" \
		--expected-desktop-reference "$(if $(DESKTOP_REF),$(DESKTOP_REF),commit:$(DESKTOP_SHA))" \
		--api-repository "$(if $(API_REPO),$(API_REPO),../yijie-api)" \
		--desktop-repository "$(if $(DESKTOP_REPO),$(DESKTOP_REPO),../yijie-desktop)" \
		"$(CONFIG)"

feat-125-local-online:
	@test -n "$(CONFIG)" || (echo "CONFIG is required" >&2; exit 2)
	@test -n "$(API_REF)$(API_SHA)" || (echo "API_REF or API_SHA is required" >&2; exit 2)
	@test -n "$(DESKTOP_REF)$(DESKTOP_SHA)" || (echo "DESKTOP_REF or DESKTOP_SHA is required" >&2; exit 2)
	NODE_EXTRA_CA_CERTS="$(CURDIR)/environments/local/generated/feat-125-caddy-root.crt" \
		node scripts/validate-feat-125-local.mjs --mode local-lab --online \
			--expected-api-reference "$(if $(API_REF),$(API_REF),commit:$(API_SHA))" \
			--expected-desktop-reference "$(if $(DESKTOP_REF),$(DESKTOP_REF),commit:$(DESKTOP_SHA))" \
			--api-repository "$(if $(API_REPO),$(API_REPO),../yijie-api)" \
			--desktop-repository "$(if $(DESKTOP_REPO),$(DESKTOP_REPO),../yijie-desktop)" \
			"$(CONFIG)"

feat-125-s7-bearer-matrix:
	NODE_EXTRA_CA_CERTS="$(CURDIR)/environments/local/generated/feat-125-caddy-root.crt" \
		node scripts/feat-125-s7-bearer-matrix.mjs

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
