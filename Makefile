SHELL := /bin/bash
DB_URL ?= postgres://presence:presence@localhost:5432/presence?sslmode=disable

.PHONY: help db-load test test-integration firmware-test run build seed fmt lint clean

help:
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN{FS=":.*?## "};{printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2}'

db-load: ## Apply schema and run invariant tests
	psql "$(DB_URL)" -v ON_ERROR_STOP=1 -f db/001_schema.sql
	psql "$(DB_URL)" -v ON_ERROR_STOP=1 -f db/002_smoke_test.sql

test: ## Unit tests (gateway) + host tests (firmware)
	cd gateway && go test ./...
	$(MAKE) firmware-test

test-integration: ## Gateway tests against a real Postgres
	# -p 1 is required, not tuning: the api and attendance suites each
	# TRUNCATE and re-seed the SAME database, so running the packages in
	# parallel (go test's default) makes them clobber each other.
	cd gateway && PRESENCE_TEST_DATABASE_URL="$(DB_URL)" go test -tags integration -p 1 ./...

firmware-test: ## Compile and run firmware logic tests on the host
	@mkdir -p .build
	g++ -std=c++17 -Wall -Wextra -O1 -o .build/fwtest \
		firmware/test/host_test.cpp firmware/src/crc32.cpp
	@./.build/fwtest

build: ## Build the gateway, recompute and seed binaries
	cd gateway && go build -o ../.build/gateway ./cmd/gateway
	cd gateway && go build -o ../.build/recompute ./cmd/recompute
	cd gateway && go build -o ../.build/seed ./cmd/seed

seed: build ## Create the bench fixture and print a device secret: make seed [RESET=1]
	./.build/seed $(if $(RESET),-reset,)

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
