COMPOSE := docker compose -f deploy/docker-compose.yml

.PHONY: gen test test-integration e2e fuzz build up down logs

gen:
	buf lint
	buf generate

test:
	go test ./...

test-integration:
	REDIS_ADDR=localhost:6379 go test -tags integration ./...

# End-to-end slice against a throwaway Redis container (needs docker and jq).
e2e:
	./scripts/e2e.sh

fuzz:
	go test -run '^$$' -fuzz=FuzzClean -fuzztime=30s ./cmd/phishcheck

build:
	go build -o bin/ ./cmd/...

up:
	$(COMPOSE) up --build -d

down:
	$(COMPOSE) down -v

logs:
	$(COMPOSE) logs -f worker
