.PHONY: dev-up dev-down dev-status feat-125-nonprod-template feat-125-nonprod-ready feat-125-nonprod-online feat-125-local-template feat-125-local-worktree-reference feat-125-local-init-secrets feat-125-local-up feat-125-local-stop feat-125-local-status feat-125-local-provision-users feat-125-local-api-db feat-125-local-prepare feat-125-local-trust-ca feat-125-local-ca-status feat-125-local-untrust-ca feat-125-local-ready feat-125-local-online feat-125-s7-bearer-matrix feat-126-s10-init-secrets feat-126-s10-config feat-126-s10-verify-images feat-126-s10-up feat-126-s10-stop feat-126-s10-status feat-126-s10-export-ca feat-126-s10-verify-runtime feat-126-s10-provision-users feat-126-s10-api-migrate feat-126-s10-api-bootstrap feat-126-s10-api-runtime-profile feat-126-s10b-preflight feat-126-s10b-api-continuation feat-126-s10b-orchestrator lint test plan apply deploy rollback

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

feat-126-s10-init-secrets:
	@test -n "$(RUN_ID)" || (echo "RUN_ID is required" >&2; exit 2)
	./scripts/init-feat-126-s10-secrets.sh "$(RUN_ID)"

feat-126-s10-config:
	@test -n "$(RUN_ID)" || (echo "RUN_ID is required" >&2; exit 2)
	./scripts/feat-126-s10-compose.sh config "$(RUN_ID)"

feat-126-s10-verify-images:
	@test -n "$(RUN_ID)" || (echo "RUN_ID is required" >&2; exit 2)
	node scripts/verify-feat-126-s10-images.mjs "$(RUN_ID)"

feat-126-s10-up:
	@test -n "$(RUN_ID)" || (echo "RUN_ID is required" >&2; exit 2)
	./scripts/feat-126-s10-compose.sh up "$(RUN_ID)"

feat-126-s10-stop:
	@test -n "$(RUN_ID)" || (echo "RUN_ID is required" >&2; exit 2)
	./scripts/feat-126-s10-compose.sh stop "$(RUN_ID)"

feat-126-s10-status:
	@test -n "$(RUN_ID)" || (echo "RUN_ID is required" >&2; exit 2)
	./scripts/feat-126-s10-compose.sh status "$(RUN_ID)"

feat-126-s10-export-ca:
	@test -n "$(RUN_ID)" || (echo "RUN_ID is required" >&2; exit 2)
	./scripts/feat-126-s10-compose.sh export-ca "$(RUN_ID)"

feat-126-s10-verify-runtime:
	@test -n "$(RUN_ID)" || (echo "RUN_ID is required" >&2; exit 2)
	node scripts/verify-feat-126-s10-runtime.mjs "$(RUN_ID)"

feat-126-s10-provision-users:
	@test -n "$(RUN_ID)" || (echo "RUN_ID is required" >&2; exit 2)
	NODE_EXTRA_CA_CERTS="$(CURDIR)/environments/local/generated/feat-126-s10/$(RUN_ID)/caddy-root.crt" \
		node scripts/feat-126-s10-provision.mjs "$(RUN_ID)"

feat-126-s10-api-migrate:
	@test -n "$(RUN_ID)" || (echo "RUN_ID is required" >&2; exit 2)
	@test -n "$(API_SHA)" || (echo "API_SHA is required" >&2; exit 2)
	./scripts/feat-126-s10-api-migration.sh "$(RUN_ID)" "$(if $(API_REPO),$(API_REPO),../yijie-api)" "$(API_SHA)"

feat-126-s10-api-bootstrap:
	@test -n "$(RUN_ID)" || (echo "RUN_ID is required" >&2; exit 2)
	@test -n "$(API_SHA)" || (echo "API_SHA is required" >&2; exit 2)
	./scripts/feat-126-s10-api-bootstrap.sh "$(RUN_ID)" "$(if $(API_REPO),$(API_REPO),../yijie-api)" "$(API_SHA)"

feat-126-s10-api-runtime-profile:
	node scripts/feat-126-s10-api-runtime-profile.mjs

feat-126-s10b-preflight:
	@test -n "$(RUN_ID)" || (echo "RUN_ID is required" >&2; exit 2)
	@test -n "$(GOVERNANCE_SHA)" || (echo "GOVERNANCE_SHA is required" >&2; exit 2)
	@test -n "$(CONTRACTS_SHA)" || (echo "CONTRACTS_SHA is required" >&2; exit 2)
	@test -n "$(API_SHA)" || (echo "API_SHA is required" >&2; exit 2)
	@test -n "$(HOST_SHA)" || (echo "HOST_SHA is required" >&2; exit 2)
	@test -n "$(DESKTOP_SHA)" || (echo "DESKTOP_SHA is required" >&2; exit 2)
	@test -n "$(RUNTIME_SHA)" || (echo "RUNTIME_SHA is required" >&2; exit 2)
	@test -n "$(INFRA_SHA)" || (echo "INFRA_SHA is required" >&2; exit 2)
	FEAT126_S10B_GOVERNANCE_SHA="$(GOVERNANCE_SHA)" \
	FEAT126_S10B_CONTRACTS_SHA="$(CONTRACTS_SHA)" \
	FEAT126_S10B_API_SHA="$(API_SHA)" \
	FEAT126_S10B_HOST_SHA="$(HOST_SHA)" \
	FEAT126_S10B_DESKTOP_SHA="$(DESKTOP_SHA)" \
	FEAT126_S10B_RUNTIME_SHA="$(RUNTIME_SHA)" \
	FEAT126_S10B_INFRA_SHA="$(INFRA_SHA)" \
		node scripts/feat-126-s10b-preflight.mjs "$(RUN_ID)"

feat-126-s10b-api-continuation:
	@test -n "$(RUN_ID)" || (echo "RUN_ID is required" >&2; exit 2)
	@test -n "$(GOVERNANCE_SHA)" || (echo "GOVERNANCE_SHA is required" >&2; exit 2)
	@test -n "$(CONTRACTS_SHA)" || (echo "CONTRACTS_SHA is required" >&2; exit 2)
	@test -n "$(API_SHA)" || (echo "API_SHA is required" >&2; exit 2)
	@test -n "$(HOST_SHA)" || (echo "HOST_SHA is required" >&2; exit 2)
	@test -n "$(DESKTOP_SHA)" || (echo "DESKTOP_SHA is required" >&2; exit 2)
	@test -n "$(RUNTIME_SHA)" || (echo "RUNTIME_SHA is required" >&2; exit 2)
	@test -n "$(INFRA_SHA)" || (echo "INFRA_SHA is required" >&2; exit 2)
	FEAT126_S10B_GOVERNANCE_SHA="$(GOVERNANCE_SHA)" \
	FEAT126_S10B_CONTRACTS_SHA="$(CONTRACTS_SHA)" \
	FEAT126_S10B_API_SHA="$(API_SHA)" \
	FEAT126_S10B_HOST_SHA="$(HOST_SHA)" \
	FEAT126_S10B_DESKTOP_SHA="$(DESKTOP_SHA)" \
	FEAT126_S10B_RUNTIME_SHA="$(RUNTIME_SHA)" \
	FEAT126_S10B_INFRA_SHA="$(INFRA_SHA)" \
		node scripts/feat-126-s10b-api-continuation.mjs "$(RUN_ID)"

feat-126-s10b-orchestrator:
	@test -n "$(RUN_ID)" || (echo "RUN_ID is required" >&2; exit 2)
	@test -n "$(GOVERNANCE_SHA)" || (echo "GOVERNANCE_SHA is required" >&2; exit 2)
	@test -n "$(CONTRACTS_SHA)" || (echo "CONTRACTS_SHA is required" >&2; exit 2)
	@test -n "$(API_SHA)" || (echo "API_SHA is required" >&2; exit 2)
	@test -n "$(HOST_SHA)" || (echo "HOST_SHA is required" >&2; exit 2)
	@test -n "$(DESKTOP_SHA)" || (echo "DESKTOP_SHA is required" >&2; exit 2)
	@test -n "$(RUNTIME_SHA)" || (echo "RUNTIME_SHA is required" >&2; exit 2)
	@test -n "$(INFRA_SHA)" || (echo "INFRA_SHA is required" >&2; exit 2)
	FEAT126_S10B_GOVERNANCE_SHA="$(GOVERNANCE_SHA)" \
	FEAT126_S10B_CONTRACTS_SHA="$(CONTRACTS_SHA)" \
	FEAT126_S10B_API_SHA="$(API_SHA)" \
	FEAT126_S10B_HOST_SHA="$(HOST_SHA)" \
	FEAT126_S10B_DESKTOP_SHA="$(DESKTOP_SHA)" \
	FEAT126_S10B_RUNTIME_SHA="$(RUNTIME_SHA)" \
	FEAT126_S10B_INFRA_SHA="$(INFRA_SHA)" \
		node scripts/feat-126-s10b-orchestrator.mjs "$(RUN_ID)"

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
