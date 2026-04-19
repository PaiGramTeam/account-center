#!/usr/bin/env sh
set -eu

COMMAND="${1:-test}"
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
COMPOSE_FILE="$REPO_ROOT/docker-compose.integration.yml"

require_docker_compose() {
  command -v docker >/dev/null 2>&1 || {
    echo "docker is required for $COMMAND" >&2
    exit 1
  }

  docker compose version >/dev/null 2>&1 || {
    echo "docker compose is required for $COMMAND" >&2
    exit 1
  }
}

cd "$REPO_ROOT"

case "$COMMAND" in
  doctor)
    go run ./cmd/integration-doctor
    ;;
  test)
	GOWORK=off go run ./cmd/integration-doctor
	GOWORK=off go test -tags=integration ./integration/...
	;;
  deps-up)
    require_docker_compose
    docker compose -f "$COMPOSE_FILE" up -d
    ;;
  deps-down)
    require_docker_compose
    docker compose -f "$COMPOSE_FILE" down
    ;;
  *)
    echo "usage: $0 {doctor|test|deps-up|deps-down}" >&2
    exit 64
    ;;
esac
