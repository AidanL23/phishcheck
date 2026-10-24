COMPOSE := docker compose -f deploy/docker-compose.yml

.PHONY: gen test test-integration build up down logs

gen:
	buf lint
	buf generate

test:
	go test ./...

test-integration:
	REDIS_ADDR=localhost:6379 go test -tags integration ./...

build:
	go build -o bin/ ./cmd/...

up:
	$(COMPOSE) up --build -d

down:
	$(COMPOSE) down -v

logs:
	$(COMPOSE) logs -f worker
