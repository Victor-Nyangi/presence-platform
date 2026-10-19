SHELL := /bin/bash
DB_URL ?= postgres://presence:presence@localhost:5432/presence?sslmode=disable

.PHONY: help db-load test test-integration firmware-test run build seed deliver fmt lint clean

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

# Monocypher is C, so it is compiled as C and linked in: the same vendored
# sources the ESP32 build links, so the OTA gate under test is the one that
# ships.
MONOCYPHER := firmware/lib/monocypher

firmware-test: ## Compile and run firmware logic tests on the host
	@mkdir -p .build
	gcc -std=c99 -Wall -Wextra -O1 -c -o .build/monocypher.o $(MONOCYPHER)/monocypher.c
	gcc -std=c99 -Wall -Wextra -O1 -c -o .build/monocypher-ed25519.o $(MONOCYPHER)/monocypher-ed25519.c
	g++ -std=c++17 -Wall -Wextra -Werror -O1 -I$(MONOCYPHER) -o .build/fwtest \
		firmware/test/host_test.cpp firmware/src/crc32.cpp \
		.build/monocypher.o .build/monocypher-ed25519.o
	@./.build/fwtest
	@# The setup-label derivation's golden vector (stdlib only, no pyserial).
	python3 -I firmware/tools/setup_label.py self-test
	@# BENCH-SECRET is compiled into esp32dev-debug only (bench_secret.h).
	python3 -I firmware/tools/check_bench_only.py

build: ## Build the gateway, recompute, seed, deliver and fwsign binaries
	cd gateway && go build -o ../.build/gateway ./cmd/gateway
	cd gateway && go build -o ../.build/recompute ./cmd/recompute
	cd gateway && go build -o ../.build/seed ./cmd/seed
	cd gateway && go build -o ../.build/deliver ./cmd/deliver
	cd gateway && go build -o ../.build/fwsign ./cmd/fwsign

seed: build ## Create the bench fixture and print a device secret: make seed [RESET=1]
	./.build/seed $(if $(RESET),-reset,)

recompute: build ## Rebuild derived attendance: make recompute ORG=<uuid> DAYS=7
	./.build/recompute -org "$(ORG)" -days "$(or $(DAYS),1)" -review

run: build ## Run the gateway
	./.build/gateway

deliver: build ## Run the outbound event delivery worker (see docs/events.md for required env)
	./.build/deliver

fmt:
	cd gateway && gofmt -w .

lint:
	cd gateway && go vet ./...

clean:
	rm -rf .build
