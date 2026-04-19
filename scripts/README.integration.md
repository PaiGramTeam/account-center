# Account Center Integration Scripts

1. Copy `.env.integration.example` to `.env.integration.local`.
2. Run `./scripts/integration.ps1 doctor` or `./scripts/integration.sh doctor`.
3. Run `./scripts/integration.ps1 test` or `./scripts/integration.sh test`.
4. Raw command: `GOWORK=off go test -tags=integration ./integration/...`.
5. Use `deps-up` / `deps-down` only when you want Docker-managed local dependencies.

## Environment File

Use `.env.integration.local` for local-only integration settings. The scripts and `cmd/integration-doctor` read the `PAI_TEST_DATABASE_*` and `PAI_TEST_REDIS_*` variables from that file or from your shell environment.

## Commands

`doctor`

Runs `go run ./cmd/integration-doctor` to print the resolved integration environment, report missing variables, and verify MySQL and Redis connectivity when the required variables are present.

`test`

Runs `go run ./cmd/integration-doctor` first, then runs `GOWORK=off go test -tags=integration ./integration/...`.

`deps-up`

Starts optional local MySQL 8 and Redis 7 dependencies with `docker compose -f docker-compose.integration.yml up -d`.

`deps-down`

Stops the optional local dependencies with `docker compose -f docker-compose.integration.yml down`.
