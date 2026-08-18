SHELL := /bin/bash
DB_URL ?= postgres://presence:presence@localhost:5432/presence?sslmode=disable

.PHONY: help db-load test test-integration firmware-test run build fmt lint clean

help:
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN{FS=":.*?## "};{printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2}'

db-load: ## Apply schema and run invariant tests
	psql "$(DB_URL)" -v ON_ERROR_STOP=1 -f db/001_schema.sql
	psql "$(DB_URL)" -v ON_ERROR_STOP=1 -f db/002_smoke_test.sql

test: ## Unit tests (gateway) + host tests (firmware)
	cd gateway && go test ./...
	$(MAKE) firmware-test

test-integration: ## Gateway tests against a real Postgres
	cd gateway && PRESENCE_TEST_DATABASE_URL="$(DB_URL)" go test -tags integration ./...

firmware-test: ## Compile and run firmware logic tests on the host
	@mkdir -p .build
	g++ -std=c++17 -Wall -Wextra -O1 -o .build/fwtest \
		firmware/test/host_test.cpp firmware/src/crc32.cpp
	@./.build/fwtest

build: ## Build the gateway and recompute binaries
	cd gateway && go build -o ../.build/gateway ./cmd/gateway
	cd gateway && go build -o ../.build/recompute ./cmd/recompute

recompute: build ## Rebuild derived attendance: make recompute ORG=<uuid> DAYS=7
	./.build/recompute -org "$(ORG)" -days "$(or $(DAYS),1)" -review

run: build ## Run the gateway
	./.build/gateway

fmt:
	cd gateway && gofmt -w .

lint:
	cd gateway && go vet ./...

clean:
	rm -rf .build
